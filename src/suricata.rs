use std::path::PathBuf;
use std::process::{Child, Command};
use crate::yaml::Suriconf;
use crate::json;
use crate::json::{Preconfiguration};
use crate::structures::CreatedLogs;
use crate::structures;
use is_executable::IsExecutable;
use std::time::Duration;
use crossbeam_channel::{select, tick};
use std::process::Stdio;
use std::io::{BufRead, BufReader};
use std::thread;

pub fn execute_suricata<'a>(suriconf: & Suriconf, vec_of_sur_cmd: &mut Vec<&str>, logs: &mut CreatedLogs) -> Option<bool>{

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
            "-s",
            "/dev/null",
            "-i",
            &suriconf.interface
        ];

        args.extend(vec_of_sur_cmd.iter().copied());

        let ctrl_c_events = if let Ok(receiver) = structures::ctrl_channel() {
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
        println!("{}", suriconf.preconf_time);
        let start = std::time::Instant::now();
        let ticks = tick(Duration::from_millis(100));


        loop {
            select! {
                recv(ticks) -> _ => {

                    if start.elapsed() >= timeout {
                        kill_suricata(&mut child);
                        break;
                    }

                    if let Ok(Some(status)) = child.try_wait() {
                        break;
                    }
                }

                recv(ctrl_c_events) -> _ => {
                    println!("Ctrl+C pressed.");
                    kill_suricata(&mut child);
                    return Some(false);
                }
            }
        }
    }
    Some(true)
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
