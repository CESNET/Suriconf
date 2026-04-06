use std::fs::{File};
use std::io::{Write, BufWriter, BufReader, BufRead};
use std::path::{PathBuf};
use serde_yaml_ng::{Value, Mapping, Sequence};
use std::fs::OpenOptions;
use crate::argument::{Commands, Args};
use crate::structures::{Analysis, CaptureMode, CreatedLogs, JsonVar, Mode, Keys, Modules};
use byte_unit::{Byte, UnitType};
use is_executable::IsExecutable;
use std::fs;
use std::process::{Command, Output};
use crate::{yaml, MANAGER_START, PACKET, RECYCLER_START};

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

#[derive(PartialEq, Eq)]
enum Interface {
    Specific,
    Default
}

impl Default for Interface {
    fn default() -> Self {
        Interface::Specific
    }
}

pub fn check_set_cpu_affinity(suricata_string: &mut Value, suriconf: &Suriconf, json_var: &mut JsonVar) -> Result<(), String> {
    let interface_spec = Interface::default();

    let set_cpu_affinity = suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
        .get_mut("set-cpu-affinity").ok_or("Unable to parse set-cpu-affinity.")?;

    if set_cpu_affinity == "no" {
        *set_cpu_affinity = Value::String("yes".to_string());
    }

    let runmode = suricata_string.get_mut("runmode").ok_or("Unable to get runmode.")?;
    if runmode != "workers" {
        *runmode = Value::String("workers".to_string());
    }

    if suriconf.modules.contains(&Modules::FlowThreads) && suriconf.modules.contains(&Modules::CpuAffinity) {
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
    else if suriconf.modules.contains(&Modules::CpuAffinity) {
        // max_cpu_usage_vec is just for worker threads
        match set_workers_set(suricata_string, suriconf, suriconf.max_cpu_usage_vec.clone()) {
            Err(e) => { return Err(e) },
            Ok(()) => {}
        }
    }
    else if suriconf.modules.contains(&Modules::FlowThreads) {
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
        let worker_interface_index = suricata_string.get("threading").ok_or("Unable to get threading section.")?.get("cpu-affinity")
            .and_then(|w| w.get("worker-cpu-set")).ok_or("Unable to parse worker-cpu-set.")?
            .get("interface-specific-cpu-set").ok_or("Unable to parse interface-specific-cpu-set.")?.as_sequence().ok_or("Unable to get interface sequence.")?
            .iter().position(|v| v["interface"] == suriconf.interface.as_str()).ok_or("Unable to find interface.")?;

        json_var.var_index.insert(
                Keys::wrk_cpu_set,
                serde_json::Value::String(worker_interface_index.to_string())
            );

        let af_packet_interface_index = suricata_string.get("af-packet").ok_or("Unable to get af-packet section.")?.as_sequence().ok_or("Unable to get interface sequence.")?
            .iter().position(|v| v["interface"] == suriconf.interface.as_str()).ok_or("Unable to find interface.")?;

        json_var.var_index.insert(
                Keys::af_packet_interface_threads,
                serde_json::Value::String(af_packet_interface_index.to_string())
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

    let mut map = Mapping::new();

    map.insert(
        Value::String("interface".into()),
        Value::String(suriconf.interface.clone())
    );

    let cpu_values = workers.iter()
        .map(|c| Value::Number((*c).into()))
        .collect();

    map.insert(
        Value::String("cpu".into()),
        Value::Sequence(cpu_values)
    );

    map.insert(
        Value::String("mode".into()),
        Value::String("exclusive".into())
    );

    let mut prio_map = Mapping::new();

    prio_map.insert(
        Value::String("high".into()),
        Value::Sequence(vec![Value::String("all".into())])
    );

    prio_map.insert(
        Value::String("default".into()),
        Value::String("medium".into())
    );

    map.insert(
        Value::String("prio".into()),
        Value::Mapping(prio_map)
    );

    let interface_value = Value::Mapping(map);

   let worker_set = worker_set.get_mut("interface-specific-cpu-set").ok_or("Unable to get interface-specific-cpu-set.")?.as_sequence_mut().ok_or("Unable to get interface-specific-cpu-set section as sequence.")?;
    worker_set.retain(|item| {
        if let Value::Mapping(map) = item {
            match map.get(&Value::String("interface".to_string())) {
                Some(Value::String(interface)) => interface != &suriconf.interface,
                _ => true,
            }
        } else {
            true
        }
    });

    worker_set.push(interface_value);

    set_interface_with_threads(suricata_string, suriconf, workers);
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
        None => { return Ok(())} // default
    };

    let interfaces = interfaces.as_sequence_mut().ok_or("Unable to get interface-specific-cpu-set section as sequence.")?;

    let mut threads = 0;
    let mut cpus: Vec<u64> = Vec::new();
    for interface in interfaces {
        if suriconf.interface == interface.as_mapping().expect("Unable to get mapping for interface.").get("interface").expect("Unable to get interface.").as_str().expect("Unable to get interface as str.") {
            let cpus_seq = interface.as_mapping().expect("Unable to get mapping for cpu.").get("cpu").expect("Unable to get cpu.").as_sequence().expect("cpu is not a sequence");
            threads = cpus_seq.len() as u64;
            cpus = cpus_seq.iter().map(|x| x.as_u64().expect("Unable to get cpu as u64.")).collect();
            break
        }
    }
    if threads > 0 {
        set_interface_with_threads(suricata_string, suriconf, cpus);
    }
    else {
        // default
    }
    Ok(())
}

pub fn check_for_default(suricata_string: &mut Value, suriconf: &Suriconf) {
    // default
    // let defalut_workers =suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
    //     .get_mut("cpu-affinity").ok_or("Unable to get cpu-affinity section.")?
}

pub fn create_nic_bash_file() -> File {
    let mut nic_file = OpenOptions::new().create(true)
        .write(true).truncate(true).open("nic_setup.sh")
        .expect("Unable to create nic_setup.sh.");
    writeln!(nic_file, "#!/bin/bash").expect("Unable to write to bash file.");
    writeln!(nic_file, "set -e").expect("Unable to write to bash file.");;
    nic_file
}
fn run_command_and_write_it_down(cmd: &str, args: &[&str], nic_file: &mut File) -> Output {
    let output = Command::new(cmd)
        .args(args)
        .output().expect("Failed to execute process.");

    if !output.status.success() {
        panic!("Process failed.");
    }

    let log_line = if cmd == "sudo" && args.get(1) == Some(&"-c") {
        format!("{} sh -c '{}'", cmd, args[2..].join(" "))
    } else {
        format!("{} {}", cmd, args.join(" "))
    };

    writeln!(nic_file, "{}", log_line).expect("Unable to write command for NIC to file.");
    output
}

pub fn af_packet_tuning(interface: &str, threads: u64, ethtool: &str, ifconfig: &str, nic_file: &mut File) {
    run_command_and_write_it_down("sudo", &["sysctl", "-w", "net.core.rmem_max=268435456"], nic_file);
    run_command_and_write_it_down("sudo", &["sysctl", "-w", "net.core.netdev_max_backlog=16384"], nic_file);

    let mut output = run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-i", interface], nic_file);


    let mut driver: Option<String> = None;

    for line in output.stdout.lines() {
        let line = line.expect("Unable to get line from stdout.");

        if  line.starts_with("driver:") {
            if let Some(value) = line.split(':').last() {
                driver = Some(value.trim().to_string())
            }
        }

        if line.starts_with("version:") {
            break;
        }
    }

    let driver = match driver {
        Some(driver) => {driver},
        None => { panic!("Unable to get  driver.")}
    };

    run_command_and_write_it_down("sudo", &[format!("{ifconfig}").as_str(), format!("{interface}").as_str(), "down"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-X", format!("{interface}").as_str(), "default"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-L", interface, "combined", &threads.to_string()], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K", interface, "rxhash", "on"], nic_file);

    if driver != "mlx5_core" {
        run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K", interface, "ntuple", "on"], nic_file);

    }

    run_command_and_write_it_down("sudo", &[format!("{ifconfig}").as_str(), format!("{interface}").as_str(), "up"], nic_file);

    output = run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-x" ,format!("{interface}").as_str()], nic_file);

    let mut found = false;
    let mut rss_length: Option<usize> = None;

    for line in output.stdout.lines() {
        let line = line.expect("Unable to get line from stdout.");

        if found {
            let value = line.trim();
            let hex_pairs = value.split(':');
            rss_length = Some(hex_pairs.count());
            found = false;
        }

        if  line.starts_with("RSS hash key:") {
            found = true;
        }
    }

    let rss_length = match rss_length {
        Some(rss_length) => {rss_length},
        None => { panic!("Unable to get RSS length.")}
    };

    let mut hash_key = String::new();
    for i in 0..rss_length {
        if i % 2 == 0 {
            hash_key.push_str("6D");
        }
        else {
            hash_key.push_str("5A");
        }

        if i+1 != rss_length {
            hash_key.push_str(":")
        }
    }

    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-X", interface, "hkey", hash_key.as_str(), "equal", format!("{threads}").as_str()], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-A", interface, "rx", "off", "tx", "off"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-C", interface, "adaptive-rx", "off", "adaptive-tx", "off", "rx-usecs", "125"], nic_file);

    output = run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-g", interface], nic_file);

    let mut found = false;
    let mut rx_descriptors_max: Option<u64> = None;

    for line in output.stdout.lines() {
        let line = line.expect("Unable to get line from stdout.");
        if line.starts_with("Pre-set maximums:") {
            found = true;
            continue;
        }

        if line.starts_with("Current hardware settings:") {
            break;
        }

        if found && line.starts_with("RX:") {
            if let Some(value) = line.split(':').last() {
                rx_descriptors_max = value.trim().parse::<u64>().ok();
            }
        }
    }

    let rx_descriptors_max = match rx_descriptors_max {
        Some(rx_descriptors_max) => {rx_descriptors_max},
        None => { panic!("Unable to get RSS queue maximum.")}
    };

    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-G", interface, "rx" , format!("{rx_descriptors_max}").as_str()], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-X", interface, "hfunc", "toeplitz"], nic_file);

    let protos = ["tcp4", "udp4", "tcp6", "udp6"];

    for proto in protos {
        run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-N", interface, "rx-flow-hash", proto, "sdfn"], nic_file);
    }
}

pub fn set_rss(interface: &str, threads: u64, ethtool: &str, nic_file: &mut File) -> u8 {
    let ethtool_l = run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-l", interface], nic_file);

    let mut found = false;
    let mut combined_max: Option<u64> = None;

    for line in ethtool_l.stdout.lines() {
        let line = line.expect("Unable to get line from stdout.");
        if line.starts_with("Pre-set maximums:") {
            found = true;
            continue;
        }

        if line.starts_with("Current hardware settings:") {
            break;
        }

        if found && line.starts_with("Combined:") {
            if let Some(value) = line.split(':').last() {
                combined_max = value.trim().parse::<u64>().ok();
            }
        }
    }

    let combined_max = match combined_max {
        Some(combined_max) => {combined_max},
        None => { panic!("Unable to get RSS queue maximum.")}
    };

    if combined_max < threads {
        eprintln!("Warning: Shrinking the CPU set to match the RSS queues: {combined_max}");
        (threads - combined_max) as u8
    }
    else {
        0
    }
}

pub fn set_hard_irq(interface: &str, cpus: &Vec<u64>, nic_file: &mut File) {
    let irqs = run_command_and_write_it_down("ls", &[format!("/sys/class/net/{interface}/device/msi_irqs/").as_str()], nic_file);

    if !irqs.status.success() {
        panic!("Process failed.");
    }

    let output_str = String::from_utf8(irqs.stdout).expect("Invalid UTF-8.");
    let mut irqs: Vec<u64> = output_str.lines().filter_map(|line| line.parse::<u64>().ok()).collect();
    irqs.sort();

    for (cpu, irq) in cpus.iter().zip(irqs.iter()) {
        run_command_and_write_it_down("sudo", &["sh", "-c", format!("echo {} > /proc/irq/{irq}/smp_affinity_list", cpu).as_str()], nic_file);
    }
    run_command_and_write_it_down("sudo", &["sh", "-c", format!("for RX_QUEUE in /sys/class/net/{interface}/queues/rx-*; do echo 0 > $RX_QUEUE/rps_cpus; done").as_str()], nic_file);
}

pub fn disable_irqbalance(nic_file: &mut File) {
    run_command_and_write_it_down("sudo", &["systemctl", "stop", "irqbalance"], nic_file);
}

pub fn disable_gro_lro(interface: &str, ethtool: &str, nic_file: &mut File) {
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K" , format!("{interface}").as_str(), "gro", "off"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K" ,format!("{interface}").as_str(), "lro", "off"], nic_file);
}

pub fn set_interface_with_threads(suricata_string: &mut Value, suriconf: &Suriconf, mut cpus: Vec<u64>) {
    let mut found = false;
    match suriconf.capture_mode {
        CaptureMode::AF_PACKET => {
            if suriconf.modules.contains(&Modules::CpuAffinity)  {
                let mut nic_file = yaml::create_nic_bash_file();
                disable_irqbalance(&mut nic_file);
                let ethtool = suriconf.ethtool_bin.to_str().expect("Unable to transform path to Ethtool to str.");
                disable_gro_lro(&suriconf.interface, ethtool, &mut nic_file);
                let shrink = set_rss(&suriconf.interface, cpus.len() as u64, ethtool, &mut nic_file);
                if shrink != 0 { // remove cpus to match RSS queues
                 cpus.drain(0..shrink as usize);
                };
                let ifconfig = suriconf.ifconfig_bin.to_str().expect("Unable to transform path to Ifconfig to str.");
                af_packet_tuning(&suriconf.interface, cpus.len() as u64, ethtool, ifconfig, &mut nic_file);
                set_hard_irq(&suriconf.interface, &cpus, &mut nic_file);
            }

            for intf in suricata_string.get_mut("af-packet").expect("Unable to get af_packet.").as_sequence_mut().expect("Unable to get sequence from af_packet.") {
                if suriconf.interface == intf.as_mapping().expect("Unable to get mapping for af_packet interface.").get("interface").expect("Unable to get interface from af_packet.").as_str().expect("Unable to get af_packet interface as str.") {
                    if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("threads") {
                        intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("threads".to_string()), Value::Number(cpus.len().into()));
                    }

                    if suriconf.modules.contains(&Modules::CpuAffinity) {
                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("tpacket-v3") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("tpacket-v3".to_string()), Value::String("yes".to_string()));
                        }

                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("mmap-locked") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("mmap-locked".to_string()), Value::String("yes".to_string()));
                        }

                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("cluster-type") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("cluster-type".to_string()), Value::String("cluster_qm".to_string()));
                        }

                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("cluster-id") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("cluster-id".to_string()), Value::Number(99.into()));
                        }

                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("ring-size") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("ring-size".to_string()), Value::Number(100000.into()));
                        }

                        if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("block-size") {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("block-size".to_string()), Value::Number(1048576.into()));
                        }
                    }

                    found = true;
                    break
                }
            }
            if !found {
                let mut new_mapping = Mapping::new();
                new_mapping.insert(Value::String("interface".to_string()), Value::String(suriconf.interface.clone()));
                new_mapping.insert(Value::String("threads".to_string()), Value::Number(cpus.len().into()));

                if suriconf.modules.contains(&Modules::CpuAffinity) {
                    new_mapping.insert(Value::String("tpacket-v3".to_string()), Value::String("yes".to_string()));
                    new_mapping.insert(Value::String("mmap-locked".to_string()), Value::String("yes".to_string()));
                    new_mapping.insert(Value::String("cluster-type".to_string()), Value::String("cluster_qm".to_string()));
                    new_mapping.insert(Value::String("cluster-id".to_string()), Value::Number(99.into()));
                    new_mapping.insert(Value::String("ring-size".to_string()), Value::Number(100000.into()));
                    new_mapping.insert(Value::String("block-size".to_string()), Value::Number(1048576.into()));
                }

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
    pub ethtool_bin: PathBuf,
    pub ifconfig_bin: PathBuf,
    pub ip_bin: PathBuf,
    pub log_dir: PathBuf,
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

    pub fn find_ifconfig_executable_file(&self) -> Result<(), String> {
        if self.ifconfig_bin.is_executable() {
            Ok(())
        } else {
            Err(String::from("Unable to parse path to Ifconfig or Ifconfig is not executable."))
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

        self.suricata_bin = if let Some(Commands::Suri {path_to_bin: Some(p), ..}) = &args.cmd  {
           p.clone()
       }
       else {
           self.find_suricata_bin(suriconf_string).expect("Unable to parse path to Suricata binary file.")
       };

        self.ethtool_bin = if let Some(Commands::Suri {ethtool_bin: Some(p), ..}) = &args.cmd  {
            p.clone()
        }
        else {
            self.find_ethtool_bin(suriconf_string).expect("Unable to parse path to Ethtool binary file.")
        };

        self.ifconfig_bin = if let Some(Commands::Suri {ifconfig_bin: Some(p), ..}) = &args.cmd  {
            p.clone()
        }
        else {
            self.find_ifconfig_bin(suriconf_string).expect("Unable to parse path to Ifconfig binary file.")
        };

        self.ip_bin = if let Some(Commands::Suri {ip_bin: Some(p), ..}) = &args.cmd  {
            p.clone()
        }
        else {
            self.find_ip_bin(suriconf_string).expect("Unable to parse path to IP binary file.")
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

    pub fn find_ifconfig_bin(&self, text: &Value) -> Option<PathBuf> {
        text.get("ifconfig-bin").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
    }

    pub fn find_ip_bin(&self, text: &Value) -> Option<PathBuf> {
        text.get("ip-bin").and_then(|c| c.as_str()).map(|c| PathBuf::from(c))
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