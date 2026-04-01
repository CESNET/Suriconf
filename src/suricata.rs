use std::path::PathBuf;
use std::process::{Child, Command};
use crate::yaml::{emergency_check_memcap, Suriconf};
use crate::{json, FLOW_WINDOW, WINDOWS};
use crate::json::{check_emergency, Preconfiguration};
use crate::structures::{Thread, SystemVar, CreatedLogs, CaptureMode, SuricataAgain, Modules};
use is_executable::IsExecutable;
use std::time::Duration;
use crossbeam_channel::{bounded, select, tick, Receiver};
use std::process::Stdio;
use std::io::{BufRead, BufReader};
use std::thread;
use sysinfo::System;
use procfs::process::{all_processes, Process};
use scirs2_core::convenience::boolean;
use signal_hook::consts::SIGINT;
use signal_hook::iterator::Signals;
use std::sync::{atomic, Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

pub fn execute_suricata<'a>(suriconf: &Suriconf, logs: &mut CreatedLogs, options: &Vec<String>) -> Option<(SystemVar, SuricataAgain)> {
    let sys = Arc::new(Mutex::new(SystemVar::default()));
    let sys_thread = Arc::clone(&sys);

    let kill = Arc::new(AtomicBool::new(false));
    let kill_thread = Arc::clone(&kill);

    let mut suricata_again = SuricataAgain::default();

    let mut vec_of_sur_cmd: Vec<String> = vec![];
    get_capture_mode(suriconf, &mut vec_of_sur_cmd);

    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "echo hello"])
            .status()
            .expect("failed to execute process");
    } else {
        if !suriconf.suricata_bin.is_executable() {
            panic!("Suricata is not executable.");
        }

        let full_path = suriconf.suricata_bin.to_str()?;
        let mut args = vec![
            full_path,
            "-c",
            &logs.suri_configuration.to_str()?,
            "-S",
            "/dev/null",
        ];

        args.extend(vec_of_sur_cmd.iter().map(|s| s.as_str()));
        args.extend(options.iter().map(|s| s.as_str()));

        let ctrl_c_events = if let Ok(receiver) = ctrl_channel() {
            receiver
        } else {
            panic!("Cannot create Ctrl+C handler.");
        };

        let ctrl_c_events_thread = ctrl_c_events.clone();

        let mut child = Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute process.");

        let stderr = child.stderr.take().expect("Failed to open stderr");
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{line}");
                }
            }
        });

        let timeout = Duration::from_secs(suriconf.preconf_time);
        let start = std::time::Instant::now();
        let ticks_thread = tick(Duration::from_millis(100));
        let cpu_usage_ticks = tick(Duration::from_secs(FLOW_WINDOW));

        let cpu_usage_thread = thread::spawn(move || {
            loop {
                select! {
                 recv(cpu_usage_ticks) -> _ => {
                        let mut sys = sys_thread.lock().expect("Unable to lock SystemVar.");
                        get_cpu_usage(&mut sys);
                }

                recv(ticks_thread) -> _ => {
                        if kill_thread.load(Ordering::SeqCst) {
                               break;
                         }
                    }

                recv(ctrl_c_events_thread) -> _ => {
                   break;
                }

                }
            }
        });

        let ticks = tick(Duration::from_millis(100));
        let emergency_ticks = tick(Duration::from_secs(FLOW_WINDOW));
        let suri_pid = check_process_name_for_suricata_main().expect("Unable to get Suricata-Main.");

        loop {
            select! {
                recv(emergency_ticks) -> _ => {
                    if check_emergency(&logs.stats) {
                        let mut sys = sys.lock().expect("Unable to lock SystemVar.");
                        emergency_check_memcap(logs, suriconf.max_memory_usage, get_workers(&mut sys));
                        suricata_again = SuricataAgain::RunAgain;
                        kill_suricata(&mut child);
                        kill.store(true, Ordering::SeqCst);
                        break;
                    }
                }

                recv(ticks) -> _ => {

                    if start.elapsed() >= timeout {
                        let mut sys = sys.lock().expect("Unable to lock SystemVar.");
                        get_cores_with_threads(suri_pid, &mut sys);
                        kill_suricata(&mut child);
                        kill.store(true, Ordering::SeqCst);
                        break;
                    }

                    if let Ok(Some(_)) = child.try_wait() {
                        kill.store(true, Ordering::SeqCst);
                        break;
                    }
                }

                recv(ctrl_c_events) -> _ => {
                    println!("Ctrl+C pressed.");
                    kill_suricata(&mut child);
                    return None;
                }
            }
        }
    cpu_usage_thread.join().expect("Cpu_usage_thread panic.");
    }

    let sys = Arc::try_unwrap(sys)
        .expect("Arc still has multiple owners with SystemVar.")
        .into_inner()
        .expect("Unable to get SystemVar behind Mutex.");

    Some((sys, suricata_again))
}

pub fn get_capture_mode(suriconf: &Suriconf, vec_of_sur_cmd: &mut Vec<String>) {
    vec_of_sur_cmd.push(
        match suriconf.capture_mode {
            CaptureMode::AF_PACKET => {format!("--af-packet={}", suriconf.interface)},
            CaptureMode::DPDK => {panic!("NOT IMPLEMENTED")}
        });
}

pub fn get_cpu_usage(sys: &mut SystemVar) {
        sys.sys.refresh_cpu_usage();

        for cpu in sys.sys.cpus() {
            let core_id: u32 = cpu.name()[3..].parse().expect("Unable to get cpu name.");
            if let Some (thread) = sys.threads.iter_mut().find(|t| t.core_id == core_id){
                thread.cpu_usage.push(cpu.cpu_usage())
            }
            else {
                sys.threads.push(Thread {name: vec![], core_id, cpu_usage: vec![cpu.cpu_usage()]});
            }
        }
}

pub fn get_workers(sys: &mut SystemVar) -> u64 {
    let mut workers: u64 = 0;

    for thread in &sys.threads {
        if thread.name.iter().any(|name| name.starts_with("W")) {
            workers += 1;
        }
    }
    workers
}

fn check_process_name_for_suricata_main() -> Option<i32> {
    for _ in 0..10 {
        for prc in all_processes().expect("Unable to get all processes.") {
            let process: Process;
            match  prc {
                Ok(prc) => {process = prc}
                Err(_) => {continue}
            }

            if process.stat().expect("Unable to find stats about process.").comm == "Suricata-Main" {
                return Some(process.pid);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}
fn get_cores_with_threads(suri_pid: i32, sys: &mut SystemVar) {
    let proc = Process::new(suri_pid).expect("Unable to create process.");
    let tasks = proc.tasks().expect("Unable to get process tasks.");

    for task in tasks {
        let stat = task.expect("Unable to get task.").stat().expect("Unable to get stat.");
        if let Some (thread) = sys.threads.iter_mut().find(|t| t.core_id ==  stat.processor.expect("Unable to get specific core.") as u32) {
            thread.name.push(stat.comm);
        }
    }
}

pub fn kill_suricata(child: &mut Child) {
    let end_timeout = Duration::from_secs(30);
    let pid = child.id();
    Command::new("sudo")
    .arg("pkill")
    .arg("Suricata-Main")
    .status()
    .expect("Unable to pkill Suricata-Main (SIGTERM).");

    let end_start = std::time::Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            println!("Process exited after SIGTERM");
            break;
        }

        if end_start.elapsed() >=  end_timeout {
            println!("Still alive, killing pid {}.", pid);
            Command::new("sudo")
                .arg("pkill")
                .arg("-SIGKILL")
                .arg("Suricata-Main")
                .status()
                .expect("Unable to pkill Suricata-Main (SIGKILL).");
            break
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn ctrl_channel() -> anyhow::Result<Receiver<()>> {
    let (sender, receiver) = bounded(100);
    let mut signals = Signals::new([SIGINT])?;

    thread::spawn(move || {
        for _ in signals.forever() {
            let _ = sender.send(());
        }
    });
    Ok(receiver)
}

pub fn check_min_suricata_runtime_for_modules(suriconf: &Suriconf) {
    if suriconf.modules.contains(&Modules::FlowThreads) && WINDOWS*120 > suriconf.preconf_time {
            panic!("Unable to execute Suricata and have enough samples from preconfiguration, \
            FlowThreads module needs at least 6 minutes.")
    }
}