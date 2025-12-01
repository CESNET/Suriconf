use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use crossbeam_channel::{bounded, Receiver};
use signal_hook::consts::signal::SIGINT;
use signal_hook::iterator::Signals;
use std::thread;
use anyhow::Result;

pub struct CreatedLogs {
    pub stats: PathBuf,
    pub suri_configuration: PathBuf,
}

impl CreatedLogs {
    pub fn new(log_dir: &PathBuf) -> Self {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!");

        let mut stats =log_dir.clone();
        stats.push("stats.json");

        let mut suri_configuration = PathBuf::from("./tmp");
        if !suri_configuration.exists() {
            fs::create_dir_all(&suri_configuration).expect("Unable to create tmp directory.");
        }

        suri_configuration.push(format!("suricata{}.yaml", n.as_secs()));
        Self {
            stats,
            suri_configuration
        }
    }
}

pub fn ctrl_channel() -> Result<Receiver<()>> {
    let (sender, receiver) = bounded(100);
    let mut signals = Signals::new([SIGINT])?;

    thread::spawn(move || {
        for _ in signals.forever() {
            let _ = sender.send(());
        }
    });
    Ok(receiver)
}