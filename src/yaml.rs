use std::fs::{File};
use std::path::{PathBuf};
use serde_yaml::Value;
use walkdir::WalkDir;
use crate::argument::{Mode, Commands,Args};

pub fn open_yaml_to_read(file: &PathBuf) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let text: Value = serde_yaml::from_reader(file)?;
    Ok(text)
}

pub fn enable_stats(stats: & Value) -> Option<bool> {
    let enabled = stats.get("enabled")?.as_str()?;

    if enabled.eq_ignore_ascii_case("no") || enabled.eq_ignore_ascii_case("false") {
        return Some(true);
    } else if !enabled.eq_ignore_ascii_case("yes") && !enabled.eq_ignore_ascii_case("true") {
        return None;
    }
    Some(false)
}

pub fn check_enable_stats_log(suricata_string: & Value, vec_of_sur_cmd: &mut Vec<&str>) -> Result<(), String> {
    if let Some(stats) = suricata_string.get("stats") {

        if let None = enable_stats(stats) {
            return Err(String::from("Unable to enable stats."));
        }
        else {
            vec_of_sur_cmd.push("--set");
            vec_of_sur_cmd.push("stats.enabled=yes");
        }

        if let Some(outputs) = suricata_string
            .get("outputs")
            .and_then(|o| o.as_sequence()) {
            for output in outputs {
                if let Some(output) = output.get("stats")  {
                    if let None = enable_stats(output) {
                        return Err(String::from("Unable to enable stats.log."));
                    }
                        vec_of_sur_cmd.push("--set");
                        vec_of_sur_cmd.push("outputs.5.stats.enabled=yes");
                        return Ok(());
                }
            }
        }
        Err(String::from("Unable to enable stats.log."))
    }
    else {
        Err(String::from("Unable to parse Suricata configuration file."))
    }
}

#[derive(Debug)]
pub struct Suriconf {
    pub suri_configuration: PathBuf,
    pub suricata_bin: PathBuf,
    pub log_dir: PathBuf,
    pub mode: Mode,
    pub modules: Vec<String>,
    pub interface: String,
    pub capture_mode: String,
    pub max_memory_usage: f64,
    pub max_cpu_usage: u64
}

impl Suriconf {
    pub fn find_suricata_executable_file(&self) -> Result<(), String> {
        for entry in WalkDir::new(&self.suricata_bin).into_iter().filter_map(|e| e.ok()) {
            if let Some(name) = entry.path().file_name(){
                // TODO check if suricata
                return Ok(());
            }
        }
        Err(String::from("Unable to parse name of Suricata executable file or file is not executable."))
    }

    pub fn init_suriconf_structure() -> Self {
        Self {
            suri_configuration: PathBuf::new(),
            suricata_bin: PathBuf::new(),
            log_dir: PathBuf::new(),
            mode: Mode::Suggestion,
            modules: vec![],
            interface: String::new(),
            capture_mode: String::new(),
            max_memory_usage: 0.0,
            max_cpu_usage: 0,
        }
    }
    pub fn create_suriconf_structure(&mut self, args: &Args, suriconf_string: &Value)  {
        self.suri_configuration = match &args.suricata_config {
            Some(cfg) => cfg.clone(),
            None => {
                self.find_suri_configuration(suriconf_string)
                    .expect("Unable to find suri-configuration.")
            }
        };

        self.mode = match &args.mode {
            Some(mode) => mode.clone(),
            None => {
                self.find_mode(suriconf_string).expect("Unable to decide Suriconf mode.")
            }
        };

        self.modules = match &args.modules {
            Some(modules) => modules.clone(),
            None => {
                self.find_modules(suriconf_string).expect("Unable to parse modules.")
            }
        };

        self.suricata_bin = if let Some(Commands::Var { common, .. }) = &args.cmd {
            common
                .path_to_bin
                .clone()
                .expect("Unable to parse path to Suricata binary file.")
        } else {
            self.find_suricata_bin(suriconf_string).expect("Unable to parse path to executable Suricata file.")
        };

        self.log_dir = if let Some(Commands::Var { common, .. }) = &args.cmd {
            common
                .path_to_logs
                .clone()
                .expect("Unable to parse path to logs.")
        } else {
            self.find_log_dir(suriconf_string).expect("Unable to parse path to logs.")
        };

        self.interface = if let Some(Commands::Var { interface: Some(interface), .. }) = &args.cmd {
            interface.clone()
        } else {
            self.find_interface(suriconf_string).expect("Unable to parse interface.")
        };

        self.capture_mode = if let Some(Commands::Var { capture_mode: Some(capture_mode), .. }) = &args.cmd {
            capture_mode.clone()
        } else {
            self.find_capture_mode(suriconf_string).expect("Unable to parse capture mode")
        };

        self.max_memory_usage = if let Some(Commands::Var { max_memory_usage: Some(max_memory_usage), .. }) = &args.cmd {
            *max_memory_usage
        } else {
            self.find_max_memory_usage(suriconf_string).expect("Unable to parse max memory usage.")
        };

        self.max_cpu_usage = if let Some(Commands::Var { max_cpu_usage: Some(max_cpu_usage), .. }) = &args.cmd {
            *max_cpu_usage
        } else {
            self.find_max_cpu_usage(suriconf_string).expect("Unable to parse max cpu usage.")
        };
    }
    pub fn find_suri_configuration(&self, text: &Value) -> Option<PathBuf> {
        text.get("suri-configuration")
            .and_then(|c| c.as_str())
            .map(|s| PathBuf::from(s))
    }

    pub fn find_mode(&self, text: &Value) -> Option<Mode> {
        let modify = text.get("mode")
            .and_then(|m| m.get("modify"))
            .and_then(|e| e.get("enabled"))
            ?.as_bool()?;

        let suggestion = text.get("mode")
            .and_then(|m| m.get("suggestion"))
            .and_then(|e| e.get("enabled"))
            ?.as_bool()?;

        if (modify && suggestion) || (!modify && !suggestion) {
            None
        } else if modify {
            let modify = text.get("mode")
                .and_then(|m| m.get("modify"))
                .and_then(|m| m.get("yaml_change"))
                ?.as_str()?;
            let mode = match modify {
                "ask" => { Some(Mode::AskModify) },
                "force" => { Some(Mode::ForceModify) },
                _ => None
            };
            mode
        } else {
            Some(Mode::Suggestion)
        }
    }

    pub fn find_modules(&self, text: &Value) -> Option<Vec<String>> {
        let mut vec_modules: Vec<String> = Vec::new();

        match text.get("modules").and_then(|v| v.as_sequence()) {
            Some(modules) => {
                for module in modules {
                    let enabled = module
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    if enabled {
                        vec_modules.push(module.get("name")
                            .and_then(|v| v.as_str())?
                            .to_string());
                    }
                }
                Some(vec_modules)
            }
            None => None
        }
    }
    pub fn find_suricata_bin(&self, text: &Value) -> Option<PathBuf> {
        text.get("suricata-bin").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_log_dir(&self, text: &Value) -> Option<PathBuf> {
        text.get("log-dir").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_interface(&self, text: &Value) -> Option<String> {
        text.get("variables")
            .and_then(|c| c.get("interface"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
    }

    pub fn find_capture_mode(&self, text: &Value) -> Option<String> {
        text.get("variables")
            .and_then(|c| c.get("capture_mode"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
    }

    pub fn find_max_memory_usage(&self, text: &Value) -> Option<f64> {
        let mut max_memory_usage_iter = text.get("variables")
            .and_then(|c| c.get("max_memory_usage"))
            .and_then(|c| c.as_str())?.split(" ");

        let number: f64 = max_memory_usage_iter.next()?.parse::<f64>().ok()?;
        let unit =  max_memory_usage_iter.next()?;
        match unit  {
            "GiB" => {Some(1_024f64 * 1_024f64 * 1_024f64 * number)},
            "MiB" => {Some(1_024f64 * 1_024f64 * number)},
            "KiB" => {Some(1_024f64 * number)},
            "B" => {Some(number)},
            _ => None
        }
    }

    pub fn find_max_cpu_usage(&self, text: &Value)  -> Option<u64>{
        text.get("variables")
            .and_then(|c| c.get("max_cpu_usage"))
            .and_then(|c| c.as_u64())
    }
}