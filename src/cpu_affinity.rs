use std::collections::{HashMap};
use serde_json::{Value, Number};
use std::fs;
use crate::json::CpuThread;
use crate::module::Module;
use crate::structures::{Analysis, Answer, Change, Keys};
use crate::{CPU_MULTIPLIER, PANIC_THRESHOLD, CPU_USAGE};
use std::process::Command;
use itertools::{izip};
use std::fs::File;
use crate::yaml;

#[derive(Debug)]
pub struct CpuAffinityModule {
    pub questions: HashMap<Keys, Value>, // changed
    pub debug: bool
}

impl Module for CpuAffinityModule {

    fn new(analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::threads_stat,
            Keys::wrk_cpu_set,
            Keys::max_cpu_usage_vec,
            Keys::interface,
            Keys::capture_mode,
            Keys::ethtool,
            Keys::ifconfig,
            Keys::capture_kernel_drops,
            Keys::capture_kernel_packets,
            Keys::capture_errors,
            Keys::decoder_pkts,
            Keys::decoder_invalid,
            Keys::ethtool_stat,
            Keys::flow_managers,
            Keys::flow_recyclers,
            Keys::ifconfig,
            Keys::af_packet_interface_threads
        ];

        let questions: HashMap<Keys, Value> =
            keys.into_iter()
                .map(|k| (k, Value::Null))
                .collect();

        Self { questions, debug }
    }

    fn questions(&self) -> &HashMap<Keys, Value> {
        &self.questions
    }

    fn main(&mut self, answers: &Vec<Answer<'_>>)-> Vec<Change> {
        self.check_drop_rate(answers);
        self.check_kernel_queue_and_rx_descriptors(answers);
        //self.check_nic_warning_counter(answers);
        self.check_rss_balancing(answers);

        let average_packets_for_percent_cpu_usage= self.analyze_average_packets_for_percent_cpu_usage(answers) as f64;
        let all_packets = self.analyze_all_capture_packets_for_decoding(answers) as f64;
        if self.debug {
            println!("average_packets_for_percent_cpu_usage: {average_packets_for_percent_cpu_usage}, all_packets: {all_packets}");
        }
        let new_workers = (all_packets / (average_packets_for_percent_cpu_usage * CPU_USAGE)).ceil() as u64;
        let new_wrk_cpu_set = Value::Array(self.set_new_cpu_set(answers, new_workers).iter()
        .map(|a| Value::Number(Number::from(*a))).collect());
        *self.questions.get_mut(&Keys::wrk_cpu_set).expect("Unable to get wrk_cpu_set from intern table.") = new_wrk_cpu_set;

        let mut nic_file = yaml::create_nic_bash_file();
        
        yaml::disable_irqbalance(&mut nic_file);
        self.module_disable_gro_lro(answers, &mut nic_file);
        self.module_set_rss(answers, &mut nic_file);
        self.module_af_packet_tuning(answers, &mut nic_file);
        self.set_af_packet_threads(answers);

        Change::collect_changes(&self.questions)
    }

}

impl CpuAffinityModule {

    fn check_nic_warning_counter(&self, answers: &Vec<Answer<'_>>) {
        let interface = self.get_interface_stat(answers);
        let ethtool = self.get_ethtool_stat(answers);

        let mut output = Command::new("sh")
            .arg("-c")
            .arg(format!("sudo {ethtool} -S {} | grep rx_crc_errors.nic: | awk '{{print $2}}'", interface))
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            let rx_crc_errors_nic = String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().expect("Failed to parse rx_crc_errors.nic as u64.");
             if  rx_crc_errors_nic > 0 {
                println!("Packets with corrupted CRC: {rx_crc_errors_nic}, continue.")
            }
        }

        output = Command::new("sh")
            .arg("-c")
            .arg(format!("sudo {ethtool} -S {} | grep rx_jabber.nic: | awk '{{print $2}}'", interface))
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            let rx_jabber_nic = String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().expect("Failed to parse rx_jabber.nic as u64.");
            if rx_jabber_nic > 0 {
                println!("Jabber packets: {rx_jabber_nic}, continue.")

            }
        }

        output = Command::new("sh")
            .arg("-c")
            .arg(format!("sudo {ethtool} -S {} | grep rx_csum_bad.nic: | awk '{{print $2}}'", interface))
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            let rx_csum_bad_nic = String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().expect("Failed to parse rx_csum_bad.nic as u64.");
            if rx_csum_bad_nic > 0 {
                println!("Packets with bad checksum: {rx_csum_bad_nic}, continue.")

            }
        }

        output = Command::new("sh")
            .arg("-c")
            .arg(format!("sudo {ethtool} -S {} | grep rx_length_errors.nic: | awk '{{print $2}}'", interface))
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            let rx_length_errors_nic = String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().expect("Failed to parse rx_length_errors.nic as u64.");
            if rx_length_errors_nic > 0 {
                println!("Packets with invalid length: {rx_length_errors_nic}, continue.")
            }
        }


        output = Command::new("sh")
            .arg("-c")
            .arg(format!("sudo {ethtool} -S {} | grep rx_oversize.nic: | awk '{{print $2}}'", interface))
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            let rx_oversize_nic = String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().expect("Failed to parse rx_oversize.nic as u64.");
            if rx_oversize_nic > 0 {
                println!("Oversized packets: {rx_oversize_nic}, continue.")
            }
        }
    }

    fn analyze_average_packets_for_percent_cpu_usage(&self, answers: &Vec<Answer<'_>>) -> u64 {
        let decoder_packets = self.get_decoder_packets_stat(answers);
        let decoder_invalid = self.get_decoder_invalid_stat(answers);
        let cpu_usage = self.get_specific_cpu_usage(answers, "W");
        let mut average: f64 = 0.0;
        let mut record: u64 = 0;

        for (decoder_packets_per_thread, cpu_usage_per_thread, decoder_invalid_per_thread) in izip!(decoder_packets.iter(), cpu_usage.iter(), decoder_invalid.iter()){
                if self.debug {
                    println!("decoder_packets_per_thread: {:?} cpu_usage_per_thread: {:?}", decoder_packets_per_thread, cpu_usage_per_thread);
                }
                let mut decoder_vec = decoder_packets_per_thread.value.clone();
                decoder_vec = self.clean_global_statistic(&decoder_vec);
                decoder_vec.drain(0..1);

                let mut decoder_in_vec = decoder_invalid_per_thread.value.clone();
                decoder_in_vec = self.clean_global_statistic(&decoder_in_vec);
                decoder_in_vec.drain(0..1);

                let mut cpu_usage_vec = cpu_usage_per_thread.cpu_usage.clone();
                cpu_usage_vec.drain(0..1);

                for (cpu_usage, decoder, decoder_in) in izip!(cpu_usage_vec.iter(), decoder_vec.iter(), decoder_in_vec.iter()) {
                    if self.debug {
                        println!("cpu_usage: {cpu_usage}, decoder: {decoder}, decoder_in: {decoder_in}");
                    }
                    if (*decoder + *decoder_in) > 0 && *cpu_usage > 0.0 {
                        let packets_per_percent_usage: f64 = ((*decoder + *decoder_in) as f32 / *cpu_usage) as f64;
                        if self.debug {
                            println!("packets_per_percent_usage: {:?}", packets_per_percent_usage);
                        }
                        record += 1;
                        average += (packets_per_percent_usage - average) / record as f64;
                    }
                }
        }
        average as u64

    }

    fn clean_global_statistic(&self, vector: &Vec<u64>) -> Vec<u64> {
        let mut clean_vector = Vec::new();
        for i in 0..vector.len() {
            let current = vector.get(i).expect("Unable to get u64.");
            if i != 0 {
                let before = vector.get(i-1).expect("Unable to get u64.");;
                 clean_vector.push(*current - *before);
            }
            else {
                clean_vector.push(*current);

            }
        }
        clean_vector
    }

    fn check_drop_rate(&self, answers: &Vec<Answer<'_>>) {
        let capture_kernel_packets_all = self.get_capture_kernel_packets_all(answers) as f64;
        let capture_kernel_drops_drops_all = self.get_capture_kernel_drops_all(answers) as f64;
        if capture_kernel_drops_drops_all > 0.0 {
            let drop_rate = (capture_kernel_drops_drops_all/capture_kernel_packets_all)*100.0;
            if self.debug {
                println!("drop-rate: {}", drop_rate);
            }
            if  drop_rate > 1.0 {
                panic!("Unable to configure Suricata, with the highest settings Suricata still drops more than 1.0 % : {drop_rate}, add more cpu cores.")
            }
        } else {
            if self.debug {
                println!("drop-rate: 0");
            }
        }

    }

    fn check_kernel_queue_and_rx_descriptors(&self, answers: &Vec<Answer<'_>>) {
        let nic_dropped = self.get_nic_dropped(answers).into_iter().max().expect("Unable to get nic_dropped maximum.") as f64;
        let nic_dropped_nic =  self.get_nic_dropped_nic(answers).into_iter().max().expect("Unable to get nic_dropped_nic maximum.") as f64;
        let capture_kernel_packets_all = self.get_capture_kernel_packets_all(answers) as f64;
        let capture_kernel_drops_drops_all = self.get_capture_kernel_drops_all(answers) as f64;
        if capture_kernel_drops_drops_all+nic_dropped+nic_dropped_nic > 0.0 {
            if self.debug {
                println!("capture_kernel_packets_all: {capture_kernel_packets_all} capture_kernel_drops_drops_all: {capture_kernel_drops_drops_all} nic_dropped: {nic_dropped} nic_dropped_nic: {nic_dropped_nic}");
            }
            let drop_rate = ((capture_kernel_drops_drops_all+nic_dropped+nic_dropped_nic)/capture_kernel_packets_all)*100.0;
            if self.debug {
                println!("drop-rate: {}", drop_rate);
            }

            println!("Dropped NIC packets: {nic_dropped}, continue.")

        } else {
            if self.debug {
                println!("Drop-rate: 0.0.");
            }
        }
    }

    fn analyze_all_capture_packets_for_decoding(&self, answers: &Vec<Answer<'_>>) -> u64 {
        let mut average_max_packets_per_thread: u64 = 0;
        let capture_kernel_packets = self.get_capture_kernel_packets_stat(answers);
        let capture_kernel_drops = self.get_capture_kernel_drops_stat(answers);

        let mut cleaned_capture_kernel_packets_vec: Vec<Vec<u64>> = Vec::new();
        let mut cleaned_capture_kernel_drops_vec: Vec<Vec<u64>> = Vec::new();
        let nic_dropped_nic = self.clean_global_statistic(&self.get_nic_dropped_nic(answers));
        let nic_dropped = self.clean_global_statistic(&self.get_nic_dropped(answers));

        for (capture_kernel_packets_per_thread, capture_kernel_drops_per_thread) in capture_kernel_packets.iter().zip(capture_kernel_drops.iter()) {
            cleaned_capture_kernel_packets_vec.push(self.clean_global_statistic(&capture_kernel_packets_per_thread.value));
            cleaned_capture_kernel_drops_vec.push(self.clean_global_statistic(&capture_kernel_drops_per_thread.value));
        }

        for i in 0..cleaned_capture_kernel_packets_vec[0].len() {
            let mut sum = 0;
            for (packets_vec, drops_vec) in cleaned_capture_kernel_packets_vec.iter().zip(cleaned_capture_kernel_drops_vec.iter()) {
                let nic_dropped_nic_val =
                        if i >= nic_dropped_nic.len() {
                            nic_dropped_nic[nic_dropped.len() - 1]
                        }
                        else {
                            nic_dropped_nic[i]
                        };

                let nic_dropped_val =
                    if i >= nic_dropped.len() {
                        nic_dropped_nic[nic_dropped.len() - 1]
                    }
                    else {
                        nic_dropped[i]
                    };

                sum += packets_vec[i] + drops_vec.get(i).expect("Unable to get drops_vec.")  + nic_dropped_nic_val;
                if self.debug {
                    println!("packets_vec[i]: {} drops_vec[i]: {} nic_dropped_nic_val: {} nic_dropped_val: {}", packets_vec[i], drops_vec[i], nic_dropped_nic_val, nic_dropped_val)
                }
            }
            sum = sum / cleaned_capture_kernel_packets_vec.len() as u64;
            if sum > average_max_packets_per_thread {
                average_max_packets_per_thread = sum;
            }
        }

        let workers = self.get_workers(answers);

        if self.debug {
            println!("cleaned_capture_kernel_packets_vec.len: {} workers: {}", cleaned_capture_kernel_packets_vec.len(), workers);
            println!("average_max_packets_per_thread: {:?}", average_max_packets_per_thread);
        }
        (average_max_packets_per_thread as f64 *workers*CPU_MULTIPLIER) as u64
    }

    fn check_rss_balancing(&self, answers: &Vec<Answer<'_>>) {
        let capture_kernel_packets = self.get_capture_kernel_packets_stat(answers);

        let values: Vec<f64> = capture_kernel_packets.iter().filter_map(|c| c.value.last().copied()).map(|v| v as f64).collect();
        let mean = values.iter().sum::<f64>() / values.len() as f64;

        let variance = values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;

        let deviation = variance.sqrt();

        let cv = deviation / mean;
        if cv > 0.5 {
            println!("Warning: Variation coefficient: {cv} signs bad load balancing.")
        }

        if self.debug {
            println!("mean: {mean}, variance: {variance}, deviation: {deviation}")
        }
    }

    fn get_interface_stat<'a>(&self, answers: &Vec<Answer<'a>>) -> &'a str {
        answers.iter().find(|h| h.key == &Keys::interface).and_then(|h| h.value.as_str()).expect("Interface cannot be found.")
    }

    fn get_ethtool_stat<'a>(&self, answers: &Vec<Answer<'a>>) -> &'a str  {
        answers.iter().find(|h| h.key == &Keys::ethtool).and_then(|h| h.value.as_str()).expect("Ethtool cannot be found.")
    }

    fn get_capture_kernel_drops_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<CpuThread> {
        answers.iter().find(|h| h.key == &Keys::capture_kernel_drops).expect("Capture kernel drops cannot be found.")
            .value.as_array().expect("Unable to get capture_kernel_drops as array.").iter().map(|v|
            {
                let obj = v.as_object().expect("Expected object.");
                let name  = obj.get("name").expect("Expected name in CpuThread structure.").as_str().expect("Unable to transform cpu name to str.").to_string();
                let value: Vec<u64> = obj.get("value").and_then(|v| v.as_array())
                .expect("Expected value in CpuThread structure.").iter().map(|num| num.as_u64().expect("Unable to transform cpu value to u64.")).collect();
                CpuThread { name, value }
            }
        ).collect()
    }

    fn get_capture_kernel_packets_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<CpuThread> {
        answers.iter().find(|h| h.key == &Keys::capture_kernel_packets).expect("Capture kernel packets cannot be found.")
            .value.as_array().expect("Unable to get capture_kernel_drops as array.").iter().map(|v|
            {
                let obj = v.as_object().expect("Expected object.");
                let name  = obj.get("name").expect("Expected name in CpuThread structure.").as_str().expect("Unable to transform cpu name to str.").to_string();
                let value: Vec<u64> = obj.get("value").and_then(|v| v.as_array())
                    .expect("Expected value in CpuThread structure.").iter().map(|num| num.as_u64().expect("Unable to transform cpu value to u64.")).collect();
                CpuThread { name, value }
            }
        ).collect()
    }

    fn get_capture_errors_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<CpuThread> {
        answers.iter().find(|h| h.key == &Keys::capture_errors).expect("Capture errors cannot be found.")
            .value.as_array().expect("Unable to get capture_kernel_drops as array.").iter().map(|v|
            {
                let obj = v.as_object().expect("Expected object.");
                let name  = obj.get("name").expect("Expected name in CpuThread structure.").as_str().expect("Unable to transform cpu name to str.").to_string();
                let value: Vec<u64> = obj.get("value").and_then(|v| v.as_array())
                    .expect("Expected value in CpuThread structure.").iter().map(|num| num.as_u64().expect("Unable to transform cpu value to u64.")).collect();
                CpuThread { name, value }
            }
        ).collect()
    }

    fn get_decoder_packets_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<CpuThread> {
        answers.iter().find(|h| h.key == &Keys::decoder_pkts).expect("Decoder packets cannot be found.")
            .value.as_array().expect("Unable to get capture_kernel_drops as array.").iter().map(|v|
            {
                let obj = v.as_object().expect("Expected object.");
                let name  = obj.get("name").expect("Expected name in CpuThread structure.").as_str().expect("Unable to transform cpu name to str.").to_string();
                let value: Vec<u64> = obj.get("value").and_then(|v| v.as_array())
                    .expect("Expected value in CpuThread structure.").iter().map(|num| num.as_u64().expect("Unable to transform cpu value to u64.")).collect();
                CpuThread { name, value }
            }
        ).collect()
    }

    fn get_decoder_invalid_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<CpuThread> {
        answers.iter().find(|h| h.key == &Keys::decoder_invalid).expect("Decoder invalid cannot be found.")
            .value.as_array().expect("Unable to get capture_kernel_drops as array.").iter().map(|v|
            {
                let obj = v.as_object().expect("Expected object.");
                let name  = obj.get("name").expect("Expected name in CpuThread structure.").as_str().expect("Unable to transform cpu name to str.").to_string();
                let value: Vec<u64> = obj.get("value").and_then(|v| v.as_array())
                    .expect("Expected value in CpuThread structure.").iter().map(|num| num.as_u64().expect("Unable to transform cpu value to u64.")).collect();
                CpuThread { name, value }
            }
        ).collect()
    }

    fn get_nic_dropped_nic(&self, answers: &Vec<Answer<'_>>) -> Vec<u64> {
        answers.iter().find(|h| h.key == &Keys::ethtool_stat).expect("Ethtool stat cannot be found.").value.as_array()
        .expect("Unable to get ethtool_stat as array.").iter().find(|obj| { obj.get("name").and_then(|n| n.as_str()) == Some("rx_dropped_nic") })
        .expect("Rx_dropped_nic not found.").get("value").and_then(|v| v.as_array()).expect("Value is not array.").iter()
        .map(|n| n.as_u64().expect("Not a number.")).collect()
    }

    fn get_nic_dropped(&self, answers: &Vec<Answer<'_>>) -> Vec<u64> {
        answers.iter().find(|h| h.key == &Keys::ethtool_stat).expect("Ethtool stat cannot be found.").value.as_array()
        .expect("Unable to get ethtool_stat as array.").iter().find(|obj| { obj.get("name").and_then(|n| n.as_str()) == Some("rx_dropped") })
        .expect("Rx_dropped_nic not found.").get("value").and_then(|v| v.as_array()).expect("Value is not array.").iter()
        .map(|n| n.as_u64().expect("Not a number.")).collect()
    }

    fn get_capture_kernel_packets_all(&self, answers: &Vec<Answer<'_>>) -> u64 {
        self.get_capture_kernel_packets_stat(answers).iter().map(|a| a.value.last().expect("Expected element.")).sum::<u64>()
    }

    fn get_capture_kernel_drops_all(&self, answers: &Vec<Answer<'_>>) -> u64 {
        self.get_capture_kernel_drops_stat(answers).iter().map(|a| a.value.last().expect("Expected element.")).sum::<u64>()
    }

    fn get_wrk_cpu_set(&self, answers: &Vec<Answer<'_>>) -> Vec<u64> {
        self.questions
            .get(&Keys::wrk_cpu_set).expect("Unable to get wrk_cpu_set.").as_array()
            .expect("wrk_cpu_set is not an array").iter()
            .map(|a| a.as_u64().expect("Expected u64 value")).collect()
    }

    pub fn set_new_cpu_set(&self, answers: &Vec<Answer<'_>>, new_workers: u64) -> Vec<u64>  {
        let max_cpu_usage_vec: Vec<u64> = answers.iter().find(|h| h.key == &Keys::max_cpu_usage_vec)
            .expect("Max cpu usage vector cannot be found.").value.as_array().expect("Unable to get array from max cpu usage vector.")
            .iter().map(|a| a.as_u64().expect("Expected u64 value")).collect();

        if self.debug {
            println!("new_workers: {new_workers}");
        }

        if new_workers > max_cpu_usage_vec.len() as u64 {
            panic!("Unable to configure Suricata, not enough cpu cores for workers.")
        }
        let mut new_wrk_cpu_set = Vec::new();
        let numa_node = self.get_interface_numa_node(answers);
        if numa_node == -1 {
            new_wrk_cpu_set = max_cpu_usage_vec[..new_workers as usize].to_vec();
        }
        else {
            let mut cpu_counter = 0;
            let numa_cpus = self.get_numa_node_with_cpus(answers, numa_node);
            for cpu in &max_cpu_usage_vec {
                if cpu_counter == new_workers  {
                    break;
                }
                if numa_cpus.contains(cpu) {
                    new_wrk_cpu_set.push(*cpu);
                    cpu_counter +=1;
                }
            }

            for cpu in &max_cpu_usage_vec {
                if cpu_counter == new_workers {
                    break;
                }
                if !numa_cpus.contains(cpu) {
                    new_wrk_cpu_set.push(*cpu);
                    cpu_counter +=1;
                }
            }
        }
        new_wrk_cpu_set
    }

    fn set_af_packet_threads(&mut self, answers: &Vec<Answer<'_>>) {
        let wrk_cpu_set_len = self.get_wrk_cpu_set(answers).len() as u64;
        *self.questions.get_mut(&Keys::af_packet_interface_threads).expect("Unable to get af_packet_interface_threads") =
            Value::Number(wrk_cpu_set_len.into());
    }

    fn get_interface_numa_node(&self, answers: &Vec<Answer<'_>>) -> i8 {
        let interface = self.get_interface_stat(answers);

        let numa_node = fs::read_to_string(
            format!("/sys/class/net/{interface}/device/numa_node")
        ).expect("Failed to read file.");

        let numa_node: i8 = numa_node
            .trim()
            .parse()
            .expect("Failed to parse number.");

        if numa_node == -1 {
            println!("Warning: interface not bounded to NUMA node.");
        }
        numa_node
    }

    fn get_numa_node_with_cpus(&self, answers: &Vec<Answer<'_>>, numa_node: i8) -> Vec<u64> {
        let numa_node_cpus = fs::read_to_string(
            format!("/sys/devices/system/node/node{numa_node}/cpulist")
        ).expect("Failed to read file.");
        numa_node_cpus.trim().split(',').map(|x| x.parse().expect("Failed to parse number.")).collect()
    }

    fn module_af_packet_tuning(&self, answers: &Vec<Answer<'_>>, nic_file: &mut File) {
        let interface = self.get_interface_stat(answers);
        let ethtool =  self.get_ethtool_stat(answers);
        let ifconfig = answers.iter().find(|h| h.key == &Keys::ifconfig).and_then(|h| h.value.as_str()).expect("Ifconfig cannot be found.");
        let wrk_cpu_set_len = self.get_wrk_cpu_set(answers).len() as u64;
        yaml::af_packet_tuning(interface, wrk_cpu_set_len, ethtool, ifconfig, nic_file);
    }

    fn module_set_rss(&self, answers: &Vec<Answer<'_>>, nic_file: &mut File) {
        let interface = self.get_interface_stat(answers);
        let ethtool =  self.get_ethtool_stat(answers);
        let wrk_cpu_set_len = self.get_wrk_cpu_set(answers).len() as u64;
        _ = yaml::set_rss(interface, wrk_cpu_set_len, ethtool, nic_file);
    }

    fn module_set_hard_irq(&self, answers: &Vec<Answer<'_>>, nic_file: &mut File) {
        let interface = self.get_interface_stat(answers);
        let wrk_cpu_set = self.get_wrk_cpu_set(answers);
        yaml::set_hard_irq(interface, &wrk_cpu_set, nic_file);
    }

    fn module_disable_gro_lro(&self, answers: &Vec<Answer<'_>>, nic_file: &mut File) {
        let interface = self.get_interface_stat(answers);
        let ethtool =  self.get_ethtool_stat(answers);
        yaml::disable_gro_lro(interface, ethtool, nic_file);
    }
}