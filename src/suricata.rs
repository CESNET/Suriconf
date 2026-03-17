use std::path::PathBuf;
use std::process::{Child, Command};
use crate::yaml::Suriconf;
use crate::{json, FLOW_WINDOW};
use crate::json::{Preconfiguration};
use crate::structures::{Thread, SystemVar, ctrl_channel, CreatedLogs, CaptureMode};
use is_executable::IsExecutable;
use std::time::Duration;
use crossbeam_channel::{select, tick};
use std::process::Stdio;
use std::io::{BufRead, BufReader};
use std::thread;
use sysinfo::System;
use procfs::process::{all_processes, Process};

pub fn execute_suricata<'a>(suriconf: &Suriconf, logs: &mut CreatedLogs) -> Option<SystemVar> {
    let mut sys: SystemVar = Default::default();

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

        let ctrl_c_events = if let Ok(receiver) = ctrl_channel() {
            receiver
        } else {
            panic!("Cannot create Ctrl+C handler.");
        };

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
        let ticks = tick(Duration::from_millis(100));
        let cpu_usage_ticks = tick(Duration::from_secs(FLOW_WINDOW));

        let suri_pid = check_process_name_for_suricata_main().expect("Unable to get Suricata-Main.");

        loop {
            select! {
                recv(cpu_usage_ticks) -> _ => {
                    get_cpu_usage(&mut sys);
                }

                recv(ticks) -> _ => {

                    if start.elapsed() >= timeout {
                        get_cores_with_threads(suri_pid, &mut sys);
                        kill_suricata(&mut child);
                        break;
                    }

                    if let Ok(Some(_)) = child.try_wait() {
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
    }
    Some(sys)
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

fn check_process_name_for_suricata_main() -> Option<i32> {
    for _ in 0..10 {
        for prc in all_processes().expect("Unable to get all processes.") {
            let process: Process;
            match  prc {
                Ok(prc) => {process = prc}
                Err(e) => {continue}
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
    let end_timeout = Duration::from_secs(10);
    let pid = child.id();
    Command::new("kill")
    .arg("-TERM")
    .arg(pid.to_string())
    .status()
    .expect("Unable to kill Suricata.");

    let end_start = std::time::Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            println!("Process exited after SIGTERM");
            break;
        }

        if end_start.elapsed() >=  end_timeout {
            println!("Still alive, killing pid {}.", pid);
            child.kill().expect("Unable to kill Suricata.");
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}
