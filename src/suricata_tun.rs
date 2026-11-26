/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file represents a Suricata configuration tuning performed before Suricata is in preconfiguration run.
*/

use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::io::{Write, BufRead};
use std::process::{Command, Output};
use chrono::{DateTime, Utc};
use serde_yaml_ng::{Value, Mapping, Sequence};
use crate::structures::{CaptureMode, JsonVar, Keys, Modules};
use crate::yaml::Suriconf;
use crate::{MANAGER_START, RECYCLER_START};

#[derive(PartialEq, Eq, Default)]
enum Interface {
    Specific,
    #[default]
    Default
}

pub fn check_set_cpu_affinity(suricata_string: &mut Value, suriconf: &Suriconf, json_var: &mut JsonVar, datetime: &DateTime<Utc>) -> Result<(), String> {
    let mgmt_cores = (RECYCLER_START + MANAGER_START) as usize;
    let available = suriconf.max_cpu_usage_vec.len();
    let flow_threads = suriconf.modules.contains(&Modules::FlowThreads);
    let cpu_affinity = suriconf.modules.contains(&Modules::CpuAffinity);

    let required = match (flow_threads, cpu_affinity) {
        (true, true) => mgmt_cores + 1, // at least one core for worker 
        (true, false) => mgmt_cores,     
        (false, true) => 1,              
        (false, false) => 0,
    };

    if available < required {
        return Err(format!("The max_cpu_usage_vec has {available} core(s), but the enabled modules need at least {required}."));
    }

    let mut interface_spec = Interface::default();

    if flow_threads && cpu_affinity {
        interface_spec = Interface::Specific;
        set_threading_section(suricata_string)?;
        set_management_section(suricata_string)?;
        set_worker_section(suricata_string)?;

        set_management_set(suricata_string, suriconf)?;
        let edited_max_cpu_usage_vec = suriconf.max_cpu_usage_vec.get((RECYCLER_START+MANAGER_START) as usize..)
        .map(|v| v.to_vec()).ok_or("Unable to parse cpu_set vector.")?;
        set_interface_specific_section(suricata_string, suriconf, edited_max_cpu_usage_vec, datetime)?;
    }
    else if cpu_affinity {
        // max_cpu_usage_vec is just for worker threads
        interface_spec = Interface::Specific;
        set_threading_section(suricata_string)?;
        set_worker_section(suricata_string)?;
        set_interface_specific_section(suricata_string, suriconf, suriconf.max_cpu_usage_vec.clone(), datetime)?;
    }
    else if flow_threads {
        // max_cpu_usage_vec is just for management threads
        set_threading_section(suricata_string)?;
        set_management_section(suricata_string)?;
        set_management_set(suricata_string, suriconf)?;
    }

    if interface_spec == Interface::Specific {
        let worker_interface_index = get_interface_specific_cpu_set(suricata_string)?
        .iter().position(|v| v["interface"] == suriconf.interface.as_str()).ok_or("Unable to find interface.")?;

        json_var.var_index.insert(
                Keys::wrk_cpu_set,
                serde_json::Value::String(worker_interface_index.to_string())
            );

        let af_packet_interface_index = get_af_packet(suricata_string)?.iter().position(|v| v["interface"] == suriconf.interface.as_str()).ok_or("Unable to find interface.")?;
        // @TODO DPDK
        // let dpdk_interface_index =  

        json_var.var_index.insert(
                Keys::af_packet_interface_threads,
                serde_json::Value::String(af_packet_interface_index.to_string())
            );
    }
    Ok(())
}

pub fn set_threading_section(suricata_string: &mut Value) -> Result<(), String> {
    match suricata_string.get_mut("threading") {
        Some(threading) => {
            let threading = threading.as_mapping_mut().ok_or("Threading section is not a mapping.")?;
            match threading.get_mut("set-cpu-affinity") {
                Some(set_cpu_affinity) => {
                    if *set_cpu_affinity == "no" {
                        *set_cpu_affinity = Value::String("yes".to_string());
                    }
                }
                None => {
                    threading.insert(Value::String("set-cpu-affinity".to_string()), Value::String("yes".to_string()));
                }
            }
        }
        None => {
            let mut threading = Mapping::new();
            threading.insert(Value::String("set-cpu-affinity".to_string()), Value::String("yes".to_string()));

            suricata_string.as_mapping_mut().ok_or("Suricata configuration is not a mapping.")?
            .insert(Value::String("threading".to_string()), Value::Mapping(threading));
        }
    }

    match suricata_string.get_mut("runmode") {
        Some(runmode) => {
            if *runmode != "workers" {
                *runmode = Value::String("workers".to_string());
            }
        }
        None => {
            suricata_string.as_mapping_mut().ok_or("Suricata configuration is not a mapping.")?
            .insert(Value::String("runmode".to_string()), Value::String("workers".to_string()));
        }
    }
    Ok(())
}

pub fn set_worker_section(suricata_string: &mut Value) -> Result<(), String> {
    let cpu_affinity = get_cpu_affinity(suricata_string)?;
    if cpu_affinity.get("worker-cpu-set").is_none() {
        cpu_affinity.as_mapping_mut().ok_or("Cpu-affinity section is not a mapping.")?
        .insert(Value::String("worker-cpu-set".to_string()), Value::Mapping(Mapping::new()));
    }
    Ok(())
}

pub fn set_management_section(suricata_string: &mut Value) -> Result<(), String> {
    let cpu_affinity = get_cpu_affinity(suricata_string)?
        .as_mapping_mut().ok_or("Cpu-affinity section is not a mapping.")?;

    match cpu_affinity.get_mut("management-cpu-set") {
        Some(management_cpu_set) => {
            let management_cpu_set = management_cpu_set.as_mapping_mut().ok_or("Management-cpu-set is not a mapping.")?;
            if management_cpu_set.get("cpu").is_none() {
                management_cpu_set.insert(Value::String("cpu".to_string()), Value::Sequence(Sequence::new()));
            }
        },
        None => {
            let mut management_cpu_set = Mapping::new();
            management_cpu_set.insert(Value::String("cpu".to_string()), Value::Sequence(Sequence::new()));
            cpu_affinity.insert(Value::String("management-cpu-set".to_string()), Value::Mapping(management_cpu_set));
        }
    }
    Ok(())
}

pub fn get_cpu_affinity(suricata_string: &mut Value) -> Result<&mut Value, String> {
    suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
    .get_mut("cpu-affinity").ok_or("Unable to get cpu-affinity section.".to_string())
}

pub fn get_worker_cpu_set(suricata_string: &mut Value) -> Result<&mut Value, String> {
    get_cpu_affinity(suricata_string)?.get_mut("worker-cpu-set")
    .ok_or("Unable to get worker-cpu-set section.".to_string())
}

pub fn get_interface_specific_cpu_set(suricata_string: &mut Value) -> Result<&mut Sequence, String> {
    get_worker_cpu_set(suricata_string)?
    .get_mut("interface-specific-cpu-set").ok_or("Unable to get interface-specific-cpu-set section.")?
    .as_sequence_mut().ok_or("Unable to get interface-specific-cpu-set section as sequence.".to_string())
}

pub fn get_af_packet(suricata_string: &mut Value) -> Result<&mut Sequence, String> {
    suricata_string.get_mut("af-packet").ok_or("Unable to get af-packet section.")?
    .as_sequence_mut().ok_or("Unable to get af-packet section as sequence.".to_string())
}

// pub fn get_dpdk() -> 

pub fn set_interface_specific_section(suricata_string: &mut Value, suriconf: &Suriconf, workers: Vec<u64>, datetime: &DateTime<Utc>) -> Result<(), String> {
    let worker_set = get_worker_cpu_set(suricata_string)?;

    if worker_set.get_mut("interface-specific-cpu-set").is_none() {
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

   let worker_set = get_interface_specific_cpu_set(suricata_string)?;
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

    set_interface_section(suricata_string, suriconf, workers, datetime);
    Ok(())
}

pub fn set_management_set(suricata_string: &mut Value, suriconf: &Suriconf) ->  Result<(), String>  {
    let management_set = get_cpu_affinity(suricata_string)?
    .get_mut("management-cpu-set").ok_or("Unable to parse management-cpu-set.")?;
    
    let management_threads: Vec<Value> =suriconf.max_cpu_usage_vec.get(0..(RECYCLER_START+MANAGER_START) as  usize)
    .ok_or("Unable to set manager thread.")?
    .iter().map(|&x| Value::from(x)).collect();

    let cpus = management_set.get_mut("cpu").ok_or("Unable to get cpus for management-cpu-set.")?;
    *cpus = Value::Sequence(management_threads);
    Ok(())
}

pub fn create_nic_bash_file(datetime: &DateTime<Utc>) -> File {
    let mut nic = PathBuf::from("./tmp");
    if !nic.exists() {
        fs::create_dir_all(&nic).expect("Unable to create tmp directory.");
    }

    nic.push(format!("nic_setup{}.sh", datetime.format("-%Y-%m-%d-%H:%M:%S")));
    let mut nic_file = OpenOptions::new().create(true)
    .write(true).truncate(true).open(nic).expect("Unable to create nic_setup.sh.");
    writeln!(nic_file, "#!/bin/bash").expect("Unable to write to bash file.");
    writeln!(nic_file, "set -e").expect("Unable to write to bash file.");
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

pub fn dpdk_tuning(interface: &str, threads: u64, nic_file: &mut File) {
    // @TODO DPDK
    todo!()
}

pub fn af_packet_tuning(interface: &str, threads: u64, ethtool: &str, ip: &str, nic_file: &mut File) {
    run_command_and_write_it_down("sudo", &["sysctl", "-w", "net.core.rmem_max=268435456"], nic_file);
    run_command_and_write_it_down("sudo", &["sysctl", "-w", "net.core.netdev_max_backlog=16384"], nic_file);

    let mut output: Output = run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-i", interface], nic_file);

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

    run_command_and_write_it_down("sudo", &[format!("{ip}").as_str(), "link", "set", format!("{interface}").as_str(), "down"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-X", format!("{interface}").as_str(), "default"], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-L", interface, "combined", &threads.to_string()], nic_file);
    run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K", interface, "rxhash", "on"], nic_file);

    if driver != "mlx5_core" {
        run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K", interface, "ntuple", "on"], nic_file);
    }

    run_command_and_write_it_down("sudo", &[format!("{ip}").as_str(), "link", "set", format!("{interface}").as_str(), "up"], nic_file);

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
        log::warn!("Shrinking the CPU set to match the RSS queues: {combined_max}.");
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

pub fn disable_offloading(interface: &str, ethtool: &str, nic_file: &mut File) {
    let offloads = ["rx", "tx", "tso", "gro", "lro", "tx", "sg", "txvlan", "rxvlan"];
    for offload in offloads {
        run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K" ,format!("{interface}").as_str(), offload , "off"], nic_file);
    }
}

pub fn create_nic_ethtool<'a>(suriconf: &'a Suriconf, datetime: &DateTime<Utc>) -> (File, &'a str) {
    let nic_file = create_nic_bash_file(datetime);
    let ethtool = suriconf.ethtool_bin.to_str().expect("Unable to transform path to Ethtool to str.");
    (nic_file, ethtool)
}

pub fn shrink_cpu_set(suriconf: &Suriconf, cpus: &mut Vec<u64>, ethtool: &str, nic_file: &mut File)  {
    let shrink = set_rss(&suriconf.interface, cpus.len() as u64, ethtool, nic_file);
    if shrink != 0 { // remove cpus to match RSS queues
        cpus.drain(0..shrink as usize);
    };
}

pub fn set_interface_section(suricata_string: &mut Value, suriconf: &Suriconf, mut cpus: Vec<u64>, datetime: &DateTime<Utc>) {
    let mut found = false;
    let cpu_affinity  = suriconf.modules.contains(&Modules::CpuAffinity);

    match suriconf.capture_mode {
        CaptureMode::AF_PACKET => {
            if cpu_affinity  {
                let (mut nic_file, ethtool) = create_nic_ethtool(suriconf, datetime);
                shrink_cpu_set(suriconf, &mut cpus, ethtool, &mut nic_file);
                disable_offloading(&suriconf.interface, ethtool, &mut nic_file);

                disable_irqbalance(&mut nic_file);
                let ip = suriconf.ip_bin.to_str().expect("Unable to transform path to Ip to str.");
                af_packet_tuning(&suriconf.interface, cpus.len() as u64, ethtool, ip, &mut nic_file);
                set_hard_irq(&suriconf.interface, &cpus, &mut nic_file);
            }

            for intf in suricata_string.get_mut("af-packet").expect("Unable to get af_packet.").as_sequence_mut().expect("Unable to get sequence from af_packet.") {
                if suriconf.interface == intf.as_mapping().expect("Unable to get mapping for af_packet interface.").get("interface").expect("Unable to get interface from af_packet.").as_str().expect("Unable to get af_packet interface as str.") {
                    if let None = intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("threads") {
                        intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("threads".to_string()), Value::Number(cpus.len().into()));
                    }

                    if suriconf.modules.contains(&Modules::CpuAffinity) {
                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("tpacket-v3").is_none() {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("tpacket-v3".to_string()), Value::String("yes".to_string()));
                        }

                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("mmap-locked").is_none() {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("mmap-locked".to_string()), Value::String("yes".to_string()));
                        }

                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("cluster-type").is_none() {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("cluster-type".to_string()), Value::String("cluster_qm".to_string()));
                        }

                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("cluster-id").is_none() {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("cluster-id".to_string()), Value::Number(99.into()));
                        }

                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("ring-size").is_none() {
                            intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").insert(Value::String("ring-size".to_string()), Value::Number(100000.into()));
                        }

                        if intf.as_mapping_mut().expect("Unable to get mapping for af_packet interface.").get_mut("block-size").is_none() {
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
        CaptureMode::DPDK => {
            if cpu_affinity  {
                let (mut nic_file, ethtool) = create_nic_ethtool(suriconf, datetime);
                shrink_cpu_set(suriconf, &mut cpus, ethtool, &mut nic_file);
                disable_offloading(&suriconf.interface, ethtool, &mut nic_file);
                panic!("DPDK not implemented")
            }

        }
    }
}