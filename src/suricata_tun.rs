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

pub fn check_set_cpu_affinity(suricata_string: &mut Value, suriconf: &Suriconf, json_var: &mut JsonVar, datetime: &DateTime<Utc>) -> Result<(), String> {
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

        match set_workers_set(suricata_string, suriconf, edited_max_cpu_usage_vec, datetime) {
            Err(e) => {panic!("{e}")},
            Ok(()) => {}
        }
    }
    else if suriconf.modules.contains(&Modules::CpuAffinity) {
        // max_cpu_usage_vec is just for worker threads
        match set_workers_set(suricata_string, suriconf, suriconf.max_cpu_usage_vec.clone(), datetime) {
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

        match check_for_interface_specific_workers_set_or_take_default(suricata_string, suriconf, datetime) {
            Err(e) => { return Err(e) }
            Ok(()) => {}
        }
    }
    else {
        match check_for_interface_specific_workers_set_or_take_default(suricata_string, suriconf, datetime) {
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

pub fn set_workers_set(suricata_string: &mut Value, suriconf: &Suriconf, workers: Vec<u64>, datetime: &DateTime<Utc>) -> Result<(), String> {
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

    set_interface_with_threads(suricata_string, suriconf, workers, datetime);
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

pub fn check_for_interface_specific_workers_set_or_take_default(suricata_string: &mut Value, suriconf: &Suriconf, datetime: &DateTime<Utc>) -> Result<(), String> {
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
        set_interface_with_threads(suricata_string, suriconf, cpus, datetime);
    }
    else {
        // default
    }
    Ok(())
}

pub fn check_for_default(_suricata_string: &mut Value, _suriconf: &Suriconf) {
    // default
    // let defalut_workers =suricata_string.get_mut("threading").ok_or("Unable to get threading section.")?
    //     .get_mut("cpu-affinity").ok_or("Unable to get cpu-affinity section.")?
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

pub fn af_packet_tuning(interface: &str, threads: u64, ethtool: &str, ip: &str, nic_file: &mut File) {
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

pub fn disable_offloading(interface: &str, ethtool: &str, nic_file: &mut File) {
    let offloads = ["rx", "tx", "tso", "gro", "lro", "tx", "sg", "txvlan", "rxvlan"];
    for offload in offloads {
        run_command_and_write_it_down("sudo", &[format!("{ethtool}").as_str(), "-K" ,format!("{interface}").as_str(), offload , "off"], nic_file);
    }
}

pub fn set_interface_with_threads(suricata_string: &mut Value, suriconf: &Suriconf, mut cpus: Vec<u64>, datetime: &DateTime<Utc>) {
    let mut found = false;
    match suriconf.capture_mode {
        CaptureMode::AF_PACKET => {
            if suriconf.modules.contains(&Modules::CpuAffinity)  {
                let mut nic_file = create_nic_bash_file(datetime);
                disable_irqbalance(&mut nic_file);
                let ethtool = suriconf.ethtool_bin.to_str().expect("Unable to transform path to Ethtool to str.");
                disable_offloading(&suriconf.interface, ethtool, &mut nic_file);
                let shrink = set_rss(&suriconf.interface, cpus.len() as u64, ethtool, &mut nic_file);
                if shrink != 0 { // remove cpus to match RSS queues
                 cpus.drain(0..shrink as usize);
                };
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