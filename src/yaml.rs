use std::fs::{File};
use std::io::{Write, BufWriter, BufReader};
use std::path::{PathBuf};
use serde_yaml_ng::Value;
use walkdir::WalkDir;
use crate::argument::{Mode, Commands,Args};
use crate::structures::CreatedLogs;

pub fn open_yaml(file: &PathBuf) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    let text: Value = serde_yaml_ng::from_reader(reader)?;
    Ok(text)
}

pub fn close_yaml(yaml: &Value, file: &PathBuf, logs: &CreatedLogs) -> Result<(), Box<dyn std::error::Error>> {

    let file = File::create(&logs.suri_configuration)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "%YAML 1.1")?;
    writeln!(writer, "---")?;

    let yaml_string = serde_yaml_ng::to_string(yaml)?;
    writer.write_all(yaml_string.as_bytes())?;

    Ok(())
}
// TODO -> to impl block for suricata.yaml -> three func below
pub fn enable_stats(stats: &Value) -> Option<bool> {
    let enabled = stats.get("enabled")?.as_str()?;

    if enabled.eq_ignore_ascii_case("no") || enabled.eq_ignore_ascii_case("false") {
        return Some(true);
    } else if !enabled.eq_ignore_ascii_case("yes") && !enabled.eq_ignore_ascii_case("true") {
        return None;
    }
    Some(false)
}

pub fn create_json_for_logging()-> Result<Value, Box<dyn std::error::Error>> {
    let required = serde_yaml_ng::from_str::<Value>(r#"
    eve-log:
      enabled: yes
      append: no
      filename: stats.json
      types:
        - stats:
      totals: yes
      threads: no
      deltas: no
    "#)?;
    Ok(required)
}

pub fn check_enable_stats_log(suricata_string: &mut Value, vec_of_sur_cmd: &mut Vec<&str>) -> Result<(), String> {
    if let Some(stats) = suricata_string.get_mut("stats") {

        let result = enable_stats(stats);
        if let None = result {
            return Err(String::from("Unable to enable stats."));
        }
        if let Some(true) = result {
            stats["enabled"] = Value::String("true".to_string());
        };

        if let Some(outputs) = suricata_string
            .get_mut("outputs")
            .and_then(|v| v.as_sequence_mut()) {
                match create_json_for_logging() {
                    Ok(required) => {
                        let exists = outputs.iter().any(|item| item == &required);
                        if !exists {
                            outputs.push(required);
                        }
                        return Ok(());
                    },
                    Err(e) => {
                        return Err(e.to_string());
                    },
                }
            }
        Err(String::from("Unable to enable stats.json."))
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
    pub preconf_time: u64,
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
            preconf_time: 0,
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
        // TODO nereaguje to na Suri
        self.suricata_bin = if let Some(Commands::Var { common, .. }) = &args.cmd {
           if let Some(path_to_bin) = &common.path_to_bin {
               path_to_bin.clone()
           }
           else {
               self.find_suricata_bin(suriconf_string).expect("Unable to parse path to Suricata binary file.")
           }
        } else {
            self.find_suricata_bin(suriconf_string).expect("Unable to parse path to executable Suricata file.")
        };

        self.log_dir = if let Some(Commands::Var { common, .. }) = &args.cmd {
            if let Some(path_to_logs) = &common.path_to_logs {
                path_to_logs.clone()
            }
            else {
                self.find_log_dir(suriconf_string).expect("Unable to parse path to logs.")
            }
        } else {
            self.find_log_dir(suriconf_string).expect("Unable to parse path to logs.")
        };

        self.preconf_time = if let Some(Commands::Var { common, .. }) = &args.cmd {
            println!("hahaha");
            if let Some(preconf_time) = &common.preconf_time {
                *preconf_time
            }
            else {
                self.find_preconf_time(suriconf_string).expect("Unable to parse time for preconfiguration.")
            }
        } else {
                self.find_preconf_time(suriconf_string).expect("Unable to parse time for preconfiguration.")
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

    pub fn find_preconf_time(&self, text: &Value) -> Option<u64> {
        text.get("preconf-time").and_then(|t| t.as_u64())
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
            _ => None // TODO some crate?
        }
    }

    pub fn find_max_cpu_usage(&self, text: &Value)  -> Option<u64>{
        text.get("variables")
            .and_then(|c| c.get("max_cpu_usage"))
            .and_then(|c| c.as_u64())
    }
}