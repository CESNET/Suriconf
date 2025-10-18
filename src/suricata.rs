use std::process::Command;
use crate::yaml::Suriconf;

pub struct Preconfiguration {
    protocols: Vec<String>,
    flows: u64,
    throughput: u64
}

impl Preconfiguration {
    pub fn new() -> Self {
        Self {
            protocols: Vec::new(),
            flows: 0,
            throughput: 0,
        }
    }

    pub fn execute_suricata<'a>(&mut self, suriconf: &'a Suriconf, vec_of_sur_cmd: &mut Vec<&'a str>) -> Option<()>{
        if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", "echo hello"])
                .status()
                .expect("failed to execute process")
        } else {
            let full_path = suriconf.suricata_bin.to_str()?;
            let mut args = vec![
                full_path,
                "-c",
                &suriconf.suri_configuration.to_str()?,
                "-s",
                "/dev/null",
                "-i",
                &suriconf.interface,
                "-vvvv",
            ];
            
            args.extend(vec_of_sur_cmd.iter().copied());
            // TODO check if the file is executable
            println!("{:?}", args);
            Command::new("sudo")
                .args(args)
                .status()
                .expect("Failed to execute process.")
        };
        Some(())

    }
}


