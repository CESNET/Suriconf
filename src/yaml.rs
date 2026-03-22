use std::fs::{File};
use std::io::{Write, BufWriter, BufReader};
use std::path::{PathBuf};
use serde_yaml_ng::{Value, Mapping, Sequence};
use walkdir::WalkDir;
use std::fs::OpenOptions;
use crate::argument::{Commands, Args};
use crate::structures::{Analysis, CaptureMode, CreatedLogs, JsonVar, Mode, Keys};
use byte_unit::{Byte, UnitType};
use crate::{MANAGER_START, PACKET, RECYCLER_START};

pub fn open_yaml(file: &PathBuf) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    let text: Value = serde_yaml_ng::from_reader(reader)?;
    Ok(text)
}

pub fn open_yaml_with_comments(file: &PathBuf) {
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
        total_used += workers*PACKET*max_pending_packets;

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

#[derive(PartialEq, Eq)]
enum Interface {
    Specific,
    Default
}

pub fn check_set_cpu_affinity(suricata_string: &mut Value, suriconf: &Suriconf, json_var: &mut JsonVar) -> Result<(), String> {
    let interface_spec = Interface::Specific;

    let set_cpu_affinity = suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
        .get_mut("set-cpu-affinity").ok_or("Unable to parse set-cpu-affinity.")?;

    if set_cpu_affinity == "no" {
        *set_cpu_affinity = Value::String("yes".to_string());
    }

    if suriconf.modules.contains(&"flow_threads".to_string()) && suriconf.modules.contains(&"cpu_affinity".to_string()) {
        match set_management_set(suricata_string, suriconf) {
            Err(e) => { return Err(e)}
            Ok(()) => {}
        }

        let edited_max_cpu_usage_vec = suriconf.max_cpu_usage_vec.get((RECYCLER_START+MANAGER_START) as usize..).map(|v| v.to_vec()).ok_or("Unable to parse cpu_set vector.")?;

        match set_workers_set(suricata_string, suriconf, edited_max_cpu_usage_vec) {
            Err(e) => {panic!("{e}")},
            Ok(()) => {}
        }
    }
    else if suriconf.modules.contains(&"cpu_affinity".to_string()) {
        // max_cpu_usage_vec is just for worker threads
        match set_workers_set(suricata_string, suriconf, suriconf.max_cpu_usage_vec.clone()) {
            Err(e) => { return Err(e) },
            Ok(()) => {}
        }
    }
    else if suriconf.modules.contains(&"flow_threads".to_string()) {
        // max_cpu_usage_vec is just for management threads
        match set_management_set(suricata_string, suriconf) {
            Err(e) => { return Err(e) }
            Ok(()) => {}
        }

        match check_for_interface_specific_workers_set_or_take_default(suricata_string, suriconf) {
            Err(e) => { return Err(e) }
            Ok(()) => {}
        }
    }
    else {
        match check_for_interface_specific_workers_set_or_take_default(suricata_string, suriconf) {
            Err(e) => { return Err(e) }
            Ok(()) => {}
        }
    };

    if interface_spec == Interface::Specific {
        let interface_index = suricata_string.get("threading").ok_or("Unable to get threading section.")?.get("cpu-affinity")
            .and_then(|w| w.get("worker-cpu-set")).ok_or("Unable to parse worker-cpu-set.")?
            .get("interface-specific-cpu-set").ok_or("Unable to parse interface-specific-cpu-set.")?.as_sequence().ok_or("Unable to get interface sequence.")?
            .iter().position(|v| v["interface"] == suriconf.interface.as_str()).ok_or("Unable to find interface.")?;
            json_var.var_index.insert(
                Keys::wrk_cpu_set,
                serde_json::Value::String(interface_index.to_string())
            );
        }
    Ok(())
}

pub fn set_workers_set(suricata_string: &mut Value, suriconf: &Suriconf, workers: Vec<u64>) -> Result<(), String> {
    let worker_set = suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?.get_mut("cpu-affinity")
        .and_then(|w| w.get_mut("worker-cpu-set")).ok_or("Unable to parse worker-cpu-set.")?;

    if let None = worker_set.get_mut("interface-specific-cpu-set") {
        worker_set.as_mapping_mut().ok_or("Unable to parse worker-cpu-set.")?
            .insert(Value::String("interface-specific-cpu-set".to_string()), Value::Sequence(Sequence::new()));
    }

    let interface_str = format!(r#"
                interface: {}
                  cpu: {:?}
                  mode: "exclusive"
                  prio:
                    high: [ "all" ]
                    "#, suriconf.interface.as_str(), workers);

    let interface_value = match serde_yaml_ng::from_str::<Value>(&interface_str) {
        Ok(interface_value) => {interface_value},
        Err(e) => {return Err("Unable to convert interface_str to Value.".to_string())}
    };

   let worker_set = worker_set.get_mut("interface-specific-cpu-set").ok_or("Unable to get interface-specific-cpu-set.")?.as_sequence_mut().ok_or("Unable to get interface-specific-cpu-set section as sequence.")?;
    worker_set.retain(|item| item != &interface_value);
        worker_set.push(interface_value);

    set_interface_with_threads(suricata_string, &suriconf.capture_mode, &suriconf.interface, workers.len() as u64);
    Ok(())
}

pub fn set_management_set(suricata_string: &mut Value, suriconf: &Suriconf) ->  Result<(), String>  {
    let management_set = suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?.get_mut("cpu-affinity")
        .and_then(|m| m.get_mut("management-cpu-set")).ok_or("Unable to parse management-cpu-set.")?;
    assert!(suriconf.max_cpu_usage_vec.len() >=  (RECYCLER_START+ MANAGER_START) as usize, "cpu_set vector provides only one core.");
    let management_threads: Vec<Value> =suriconf.max_cpu_usage_vec.get(0..(RECYCLER_START+MANAGER_START) as  usize).ok_or("Unable to set manager thread.")?
        .iter().map(|&x| Value::from(x)).collect();
    let cpus = management_set.get_mut("cpu").ok_or("Unable to get cpus for management-cpu-set.")?;
    *cpus = Value::Sequence(management_threads);
    Ok(())
}

pub fn check_for_interface_specific_workers_set_or_take_default(suricata_string: &mut Value, suriconf: &Suriconf) -> Result<(), String> {
    let interfaces = suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
        .get_mut("cpu-affinity").ok_or("Unable to get cpu-affinity section.")?
        .get_mut("worker-cpu-set").ok_or("Unable to get worker-cpu-set section.")?.get_mut("interface-specific-cpu-set");

    let interfaces = match interfaces {
        Some(interfaces) => {interfaces},
        None => { return Ok(())} // TODO default
    };

    let interfaces = interfaces.as_sequence_mut().ok_or("Unable to get interface-specific-cpu-set section as sequence.")?;

    let mut threads = 0;
    for interface in interfaces {
        if suriconf.interface == interface.as_mapping().expect("Unable to get mapping for interface.").get("interface").expect("Unable to get interface.").as_str().expect("Unable to get interface as str.") {
            threads = interface.as_mapping().expect("Unable to get mapping for cpu.").get("cpu").expect("Unable to get cpu.").as_sequence().expect("cpu is not a sequence").len() as u64;
            break
        }
    }
    if threads > 0 {
        set_interface_with_threads(suricata_string, &suriconf.capture_mode, &suriconf.interface, threads);
    }
    else {
        // TODO default
    }
    Ok(())
}

pub fn check_for_default(suricata_string: &mut Value, suriconf: &Suriconf) {
    todo!()
    // default
    // let defalut_workers =suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
    //     .get_mut("cpu-affinity").ok_or("Unable to get cpu-affinity section.")?
}

pub fn set_interface_with_threads(suricata_string: &mut Value, capture_mode: &CaptureMode, interface: &str, threads: u64) {
    let mut found = false;
    match capture_mode {
        CaptureMode::AF_PACKET => {
            for intf in suricata_string.get_mut("af-packet").expect("Unable to get af_packet.").as_sequence_mut().expect("Unable to get sequence from af_packet.") {
                if interface == intf.as_mapping().expect("Unable to get mapping for af_packet interface.").get("interface").expect("Unable to get interface from af_packet.").as_str().expect("Unable to get af_packet interface as str.") {
                    if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("threads") {
                        intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("threads".to_string()), Value::Number(threads.into()));
                    }
                    found = true;
                    break
                }
            }
            if !found {
                let mut new_mapping = Mapping::new();
                new_mapping.insert(Value::String("interface".to_string()), Value::String(interface.to_string()));
                new_mapping.insert(Value::String("threads".to_string()), Value::Number(threads.into()));
                suricata_string.get_mut("af-packet").expect("Unable to get af_packet.").as_sequence_mut().expect("Unable to get sequence from af_packet.").push(Value::Mapping(new_mapping))
            }
        },
        CaptureMode::DPDK => {panic!("NOT IMPLEMENTED!")}
    }
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
    pub log_dir: PathBuf,
    pub preconf_time: u64,
    pub analysis: Analysis,
    pub mode: Mode,
    pub modules: Vec<String>,
    pub interface: String,
    pub capture_mode: CaptureMode,
    pub max_memory_usage: u64,
    pub max_cpu_usage_vec: Vec<u64>
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

        self.suricata_bin = if let Some(Commands::Suri {path_to_bin: Some(p), ..}) = &args.cmd  {
               p.clone()
           }
           else {
               self.find_suricata_bin(suriconf_string).expect("Unable to parse path to Suricata binary file.")
           };

        self.log_dir = if let Some(Commands::Suri { path_to_logs: Some(p), .. }) = &args.cmd {
                p.clone()
            }
            else {
                self.find_log_dir(suriconf_string).expect("Unable to parse path to logs.")
            };

        self.preconf_time = if let Some( Commands::Suri { preconf_time: Some(p), .. }) = &args.cmd {
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

        self.max_cpu_usage_vec = if let Some(Commands::Var { max_cpu_usage_vec: Some(max_cpu_usage_vec), .. }) = &args.cmd {
            max_cpu_usage_vec.clone()
        }  else {
            self.find_max_cpu_usage_vec(suriconf_string).expect("Unable to parse max cpu usage vector.")
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

    pub fn find_max_cpu_usage_vec(&self, text: &Value)  -> Option<Vec<u64>>{
        let mut vec_cpus: Vec<u64> = Vec::new();
        match text.get("variables")
            .and_then(|c| c.get("max_cpu_usage_vec"))
            .and_then(|v| v.as_sequence()) {
            Some(vec_cpus_value ) => {
                for cpu in vec_cpus_value {
                     vec_cpus.push(cpu.as_u64().expect("Unable to convert cpu_set to vector."))
                }
            },
            None => {return None}
        }
        Some(vec_cpus)
    }
}