/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file represents a yaml parser.
*/

use std::fs::{File};
use std::io::{Write, BufWriter, BufReader};
use std::path::{PathBuf};
use serde_yaml_ng::{Value, Mapping};
use std::fs::OpenOptions;
use crate::argument::{Commands, Args};
use crate::structures::{Analysis, CaptureMode, CreatedLogs, Mode, Modules};
use byte_unit::{Byte, UnitType};
use is_executable::IsExecutable;
use std::fs;
use crate::PACKET;
use std::collections::{HashSet};

pub fn open_yaml(file: &PathBuf) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    let text: Value = serde_yaml_ng::from_reader(reader)?;
    Ok(text)
}

pub fn open_yaml_with_comments(_file: &PathBuf) {
    todo!()
}

pub fn yaml_to_json(yaml: Value) -> serde_json::Value {
    serde_json::to_value(yaml).expect("Unable to transform yaml to json.")
}

pub fn json_to_yaml(json: serde_json::Value) -> Value {
    serde_yaml_ng::to_value(json).expect("Unable to transform json to yaml.")
}

pub fn close_yaml(yaml: &Value, file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {

    let file = File::create(file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "%YAML 1.1")?;
    writeln!(writer, "---")?;

    let yaml_string = serde_yaml_ng::to_string(yaml)?;
    writer.write_all(yaml_string.as_bytes())?;

    Ok(())
}

pub fn emergency_check_memcap(logs: &mut CreatedLogs, max_memory_usage: u64, workers: u64) {

        let mut suricata_file = match open_yaml(&logs.suri_configuration) {
            Ok(suricata_file) => {suricata_file},
            Err(e) => { panic!("{e}")}
        };

        let mut total_used: u64 = 0;

        let defrag_memcap_str = suricata_file.get("defrag").and_then(|d| d.get("memcap")).expect("Unable to get defrag_memcap for emergency check.").as_str().expect("Unable to get defrag_memcap as str.");
        total_used += Byte::parse_str(defrag_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert defrag_memcap to Bytes.");

        let stream_memcap_str = suricata_file.get("stream").and_then(|s| s.get("memcap")).expect("Unable to get stream_memcap for emergency check.").as_str().expect("Unable to get stream_memcap as str.");
        total_used += Byte::parse_str(stream_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert stream_memcap to Bytes.");


        let reassembly_memcap_str = suricata_file.get("stream").and_then(|s| s.get("reassembly")).and_then(|r| r.get("memcap")).expect("Unable to get reassembly_memcap for emergency check.").as_str().expect("Unable to get reassembly_memcap as str.");
        total_used += Byte::parse_str(reassembly_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert reassembly_memcap to Bytes.");

        let ippair_memcap_str = suricata_file.get("ippair").and_then(|i| i.get("memcap")).expect("Unable to get ippair_memcap for emergency check.").as_str().expect("Unable to get ippair_memcap as str.");
        total_used += Byte::parse_str(ippair_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert ippair_memcap to Bytes.");

        let host_memcap_str = suricata_file.get("host").and_then(|h| h.get("memcap")).expect("Unable to get host_memcap for emergency check.").as_str().expect("Unable to get host_memcap as str.");
        total_used += Byte::parse_str(host_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert host_memcap to Bytes.");

        let max_pending_packets = suricata_file.get("max-pending-packets").and_then(|m| m.as_u64()).expect("Unable to transform max-pending-packets as u64.");
        total_used += workers*(PACKET as u64)*max_pending_packets;

        let flow_memcap = suricata_file.get_mut("flow").and_then(|h| h.get_mut("memcap")).expect("Unable to get flow_memcap for emergency check.");
        let flow_memcap_str =  flow_memcap.as_str().expect("Unable to get flow_memcap as str.");
        let flow_memcap_bytes = Byte::parse_str(flow_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert flow_memcap to Bytes.");
        total_used += flow_memcap_bytes;

        if total_used >= max_memory_usage {
            panic!("Unable to increase flow_memcap, emergency mode is unavoidable. Consider to increase max_memory_usage in suriconf.yaml.");
        }

        else {
            let free = max_memory_usage - total_used;
            let new_flow_flow_memcap = free + flow_memcap_bytes;
            *flow_memcap = Value::String(Byte::from_u64(new_flow_flow_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            match close_yaml(&suricata_file, &logs.suri_configuration) {
                Err(e) => {panic!("{e}")},
                Ok(()) => {}
            }
        }

        truncate_file(&logs.stats);
        truncate_file(&logs.flows);
}

pub fn truncate_file(log_file: &PathBuf) {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(log_file)
        .expect("Unable to truncate file.");
}

pub fn enable_stats(stats: &Value) -> Option<bool> {
    let enabled = stats.get("enabled")?.as_str()?;

    if enabled.eq_ignore_ascii_case("no") || enabled.eq_ignore_ascii_case("false") {
        return Some(true);
    } else if !enabled.eq_ignore_ascii_case("yes") && !enabled.eq_ignore_ascii_case("true") {
        return None;
    }
    Some(false)
}

enum EveLogType {
    Flow,
    Stats
}

fn create_json_for_logging(enabled: bool, stats: EveLogType)-> Result<Value, Box<dyn std::error::Error>> {
    let required;
    match stats {
         EveLogType::Flow => {
              required = format!(r#"
                eve-log:
                  enabled: {}
                  append: no
                  filename: stats.json
                  types:
                    - stats:
                        totals: yes
                        threads: yes
                        deltas: no
                        null-values: true
                "#,
                if enabled { "yes" } else { "no" },
                 );
         },
        EveLogType::Stats => {
            required = format!(r#"
                eve-log:
                  enabled: {}
                  append: no
                  filename: flows.json
                  types:
                    - flow:
                "#,
               if enabled { "yes" } else { "no" },
                );
        }
    }

    let required = serde_yaml_ng::from_str::<Value>(&required)?;
    Ok(required)
}

pub fn disable_logging(suricata_string: &mut Value) -> Result<(), String> {
    let outputs = suricata_string
        .get_mut("logging")
        .and_then(|v| v.get_mut("outputs"))
        .and_then(|v| v.as_sequence_mut())
        .ok_or_else(|| String::from("Unable to find logging outputs in Suricata configuration."))?;

    for o in outputs.iter_mut() {
        if let Some(m) = o.as_mapping_mut() {
            for key in ["file", "syslog"] {
                if let Some(inner) = m.get_mut(key).and_then(|v| v.as_mapping_mut()) {
                    inner.insert(
                        Value::String("enabled".into()),
                        Value::String("no".into()),
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn check_enable_stats_log(suricata_string: &mut Value) -> Result<(), String> {
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
                for o in outputs.iter_mut() {
                    if let Some(m) = o.as_mapping_mut() {
                        for v in m.values_mut() {
                            if let Some(inner) = v.as_mapping_mut() {
                                inner.insert(
                                    Value::String("enabled".into()),
                                    Value::String("no".into()),
                                );
                            }
                        }
                    }
                }

                for (enabled, log_type) in [
                    (false, EveLogType::Stats),
                    (false, EveLogType::Flow),
                    (true,  EveLogType::Stats),
                    (true,  EveLogType::Flow),
                ] {
                    match create_json_for_logging(enabled, log_type) {
                        Ok(required) => {
                            if enabled {
                                outputs.push(required);
                            } else {
                                outputs.retain(|item| item != &required);
                            }
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
        }
        else {
            return Err(String::from("Unable to enable stats.json."))
        }
    }
    else {
        return Err(String::from("Unable to parse Suricata configuration file."))
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Suriconf {
    pub suri_configuration: PathBuf,
    pub suricata_bin: PathBuf,
    pub ethtool_bin: PathBuf,
    pub ip_bin: PathBuf,
    pub log_dir: PathBuf,
    pub socket: PathBuf,
    pub preconf_time: u64,
    pub analysis: Analysis,
    pub mode: Mode,
    pub modules: Vec<Modules>,
    pub interface: String,
    pub capture_mode: CaptureMode,
    pub max_memory_usage: u64,
    pub max_cpu_usage_vec: Vec<u64>
}

impl Suriconf {
    pub fn find_suricata_executable_file(&self) -> Result<(), String> {
        if self.suricata_bin.is_executable() {
            Ok(())
        } else {
            Err(String::from("Unable to parse path to Suricata or Suricata is not executable."))
        }
    }

    pub fn find_ethtool_executable_file(&self) -> Result<(), String> {
        if self.ethtool_bin.is_executable() {
            Ok(())
        } else {
            Err(String::from("Unable to parse path to Ethtool or Ethtool is not executable."))
        }
    }

    pub fn find_ip_executable_file(&self) -> Result<(), String> {
        if self.ip_bin.is_executable() {
            Ok(())
        } else {
            Err(String::from("Unable to parse path to IP or IP is not executable."))
        }
    }

    pub fn check_read_write_for_log_dir(&self) -> Result<(), String> {
        if !fs::read_dir(&self.log_dir).is_ok() {
            return Err(String::from("Unable to read log directory."));
        }

        let temp_file = &self.log_dir.join(".test");
        if File::create(&temp_file).is_ok() {
            let _ = fs::remove_file(temp_file);
        } else {
            return Err(String::from("Unable to write to log directory."));
        }
        Ok(())
    }

    pub fn init_suriconf_structure() -> Self {
        Self::default()
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

        self.suricata_bin = if let Some(Commands::Suricata {path_to_bin: Some(p), ..}) = &args.cmd  {
           p.clone()
       }
       else {
           self.find_suricata_bin(suriconf_string).expect("Unable to parse path to Suricata binary file.")
       };

        self.ethtool_bin = if let Some(Commands::Suricata {ethtool_bin: Some(p), ..}) = &args.cmd  {
            p.clone()
        }
        else {
            self.find_ethtool_bin(suriconf_string).expect("Unable to parse path to Ethtool binary file.")
        };

        self.ip_bin = if let Some(Commands::Suricata {ip_bin: Some(p), ..}) = &args.cmd  {
            p.clone()
        }
        else {
            self.find_ip_bin(suriconf_string).expect("Unable to parse path to IP binary file.")
        };

        self.log_dir = if let Some(Commands::Suricata { path_to_logs: Some(p), .. }) = &args.cmd {
            p.clone()
        }
        else {
            self.find_log_dir(suriconf_string).expect("Unable to parse path to logs.")
        };

        self.socket = if let Some(Commands::Suricata { path_to_socket: Some(p), .. }) = &args.cmd {
            p.clone()
        }
        else {
            self.find_socket(suriconf_string).expect("Unable to parse path to unix socket.")
        };

        self.preconf_time = if let Some( Commands::Suricata { preconf_time: Some(p), .. }) = &args.cmd {
        p.clone()
        }
        else {
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

        let result = if let Some(Commands::Var { max_cpu_usage_vec: Some(max_cpu_usage_vec), .. }) = &args.cmd {
            parse_cpu_list(&max_cpu_usage_vec)
        }  else {
            self.find_max_cpu_usage_vec(suriconf_string)
        };

        self.max_cpu_usage_vec = match result {
            Ok(cpus) => cpus,
            Err(msg) => panic!("Unable to parse max cpu usage vector: {msg}"),
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

    pub fn find_modules(&self, text: &Value) -> Option<Vec<Modules>> {
        let mut vec_modules: Vec<Modules> = Vec::new();

        match text.get("modules").and_then(|v| v.as_sequence()) {
            Some(modules) => {
                for module in modules {
                    let enabled = module
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    if enabled {
                        let module_str = module.get("name")
                            .and_then(|v| v.as_str())?;
                        vec_modules.push(Modules::new(module_str));
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

    pub fn find_ethtool_bin(&self, text: &Value) -> Option<PathBuf> {
        text.get("ethtool-bin").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_ip_bin(&self, text: &Value) -> Option<PathBuf> {
        text.get("ip-bin").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_log_dir(&self, text: &Value) -> Option<PathBuf> {
        text.get("log-dir").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_socket(&self, text: &Value) -> Option<PathBuf> {
        text.get("socket").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_preconf_time(&self, text: &Value) -> Option<u64> {
        text.get("preconf-time").and_then(|t| t.as_u64())
    }

    pub fn find_analysis(&self, text: &Value) -> Option<Analysis> {
        text.get("analysis").and_then(|a| a.as_str())
            .and_then(|a| match a {
            "static" => Some(Analysis::Static),
            "dynamic" => Some(Analysis::Dynamic),
            _ => None,
        })
    }

    pub fn find_interface(&self, text: &Value) -> Option<String> {
        text.get("variables")
            .and_then(|c| c.get("interface"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
    }

    pub fn find_capture_mode(&self, text: &Value) -> Option<CaptureMode> {
        text.get("variables")
            .and_then(|c| c.get("capture_mode"))
            .and_then(|c| c.as_str()).and_then(|a| match a {
            "dpdk" => Some(CaptureMode::DPDK),
            "af_packet" => Some(CaptureMode::AF_PACKET),
            _ => None
        })
    }

    pub fn find_max_memory_usage(&self, text: &Value) -> Option<u64> {
        let max_memory_usage = text.get("variables")
            .and_then(|c| c.get("max_memory_usage"))
            .and_then(|c| c.as_str())?;

        let byte: Option<u64> = Byte::parse_str(max_memory_usage, true)
            .ok()
            .map(|b| b.as_u64());
        byte
    }

    pub fn find_max_cpu_usage_vec(&self, text: &Value) -> Result<Vec<u64>, String> {
        let seq = text
            .get("variables")
            .and_then(|c| c.get("max_cpu_usage_vec"))
            .and_then(|v| v.as_sequence())
            .ok_or_else(|| "Missing 'max_cpu_usage_vec' in Suriconf configuration".to_string())?;


        let mut cpus: Vec<u64> = Vec::new();
        let mut seen = HashSet::new();

        for item in seq {
            let s = match item {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                u => return Err(format!("Invalid CPU {:?}.", u))

            };

            insert_cpu(&s, &mut seen, &mut cpus)?;
        }
        Ok(cpus)        
    }
}

fn parse_cpu_list(items: &[String]) -> Result<Vec<u64>, String>  {
    let mut cpus = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        insert_cpu(item, &mut seen, &mut cpus)?;
    }
    Ok(cpus)
}

pub fn expand_cpu_range(s: &str) -> Result<Vec<u64>, String>  {
    let system_cpus = num_cpus::get();
    let s = s.trim();
    match s.split_once('-') {
        Some((start, end)) => {
            let start: u64 = start.trim().parse().map_err(|_| format!("Invalid CPU {}.", start))?;
            let end: u64 = end.trim().parse().map_err(|_| format!("Invalid CPU {}.", end))?;
            if start <= end {
                if (end as usize) < system_cpus {
                    Ok((start..=end).collect())
                } else {
                    Err(format!("CPU {} is not available.", end))
                }
            } else {
                Err(format!("Invalid CPU range '{}-{}', start must not be greater than end.", start, end))
            }
        }
        None => {
            let cpu: u64 = s.parse().map_err(|_| format!("Invalid CPU {}.", s))?;
            if (cpu as usize) < system_cpus {
                Ok(vec![cpu])
            } else {
                Err(format!("CPU {} is not available.", cpu))
            }
        }
    }
}

pub fn insert_cpu(s: &str, seen: &mut HashSet<u64>, cpus: &mut Vec<u64>) -> Result<(), String> {
    for cpu in expand_cpu_range(s)? {
        if seen.insert(cpu) {
            cpus.push(cpu);
        }
    }
    Ok(())
}

pub fn fix_interface_cpu_set(suricata_string: &mut Value)  {
        let interface_spec_cpu_sets  = suricata_string.get_mut("threading").expect("Unable to get threading.").get_mut("cpu-affinity").expect("Unable to get cpu-affinity.")
            .get_mut("worker-cpu-set").expect("Unable to get worker-cpu-set.").get_mut("interface-specific-cpu-set").expect("").as_sequence_mut().expect("Unable to get interface-specific-cpu-set.");

            for item in interface_spec_cpu_sets {
                if let Value::Mapping(map) = item {

                    let interface = map.remove(&Value::String("interface".into()));
                    let cpu = map.remove(&Value::String("cpu".into()));
                    let mode = map.remove(&Value::String("mode".into()));
                    let prio = map.remove(&Value::String("prio".into()));

                    let mut new_map = Mapping::new();

                    if let Some(v) = interface {
                        new_map.insert(Value::String("interface".into()), v);
                    }
                    if let Some(v) = cpu {
                        new_map.insert(Value::String("cpu".into()), v);
                    }
                    if let Some(v) = mode {
                        new_map.insert(Value::String("mode".into()), v);
                    }
                    if let Some(v) = prio {
                        new_map.insert(Value::String("prio".into()), v);
                    }

                    *map = new_map;
                }
            }
}