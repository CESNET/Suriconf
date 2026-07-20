/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>

This file represents universal trait for modules.
*/

use byte_unit::Byte;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use crate::{FLOW_WINDOW, MIN_RUN, PACKET, ROB_REGRESSION, WINDOWS};
use crate::regression::{my_huber_regression, my_theil_sen_regression};
use crate::structures::{Analysis, Answer, Change, Keys, RobRegression, Thread, MemcapChange, Reason, Flow};

pub trait Module {
    fn new(analysis: &Analysis, debug: bool) -> Self where Self: Sized;

    fn questions(&self) -> &HashMap<Keys, Value>;

    fn init_questions(&self) -> Vec<Keys> {
        self.questions().keys().copied().collect()
    }
    fn main(&mut self, answers: &Vec<Answer<'_>>) -> Vec<Change>;

    fn get_load_factor(&self, objects_active: i64, hash_size: f64) -> f64{
        objects_active as f64 / hash_size
    }

    fn get_recyclers_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
        answers.iter().find(|h| h.key == &Keys::flow_recyclers).expect("Unable to get flow_managers.").value.as_f64().expect("Unable to transform flow_managers to f64.")
    }

    fn get_managers_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
        answers.iter().find(|h| h.key == &Keys::flow_managers).expect("Unable to get flow_managers.").value.as_f64().expect("Unable to transform flow_managers to u64.")
    }

    fn get_uptime_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        *answers.iter().find(|h| h.key == &Keys::uptime).expect("Unable to get uptime.").value
            .as_array().expect("Unable to create array from uptime record.").iter().map(|a| a.as_u64().expect("Unable to transform uptime to u64.")).collect::<Vec<u64>>().last().expect("Unable to get last uptime.")
    }
    
    fn get_max_pending_packets(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a | a.key == &Keys::max_pending_packets).and_then(|a| a.value.as_u64()).expect("Unable to get max_pending_packets as u64.")
    }

    fn get_default_packet_size(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::default_packet_size).expect("Unable to get default packet size.").value.as_u64().expect("Unable to get default packet size as u64.")
    }

    fn get_thread_stat<'a>(&self, answers: &Vec<Answer<'a>>) -> &'a Vec<Value> {
         answers.iter().find(|h| h.key == &Keys::threads_stat).expect("Unable to get threads_stat.").value
            .as_array().expect("Unable to create array from mgr_cpu_usage record.")
    }

    fn get_flow_mgr_full_result(&self, answers: &Vec<Answer<'_>>, debug: bool) -> Vec<f64> {
        let mut flow_mgr_full_hash_pass = answers.iter().find(|h| h.key == &Keys::flow_mgr_full_hash_pass).expect("Unable to get flow_mgr_full_hash_pass.").value
            .as_array().expect("Unable to create array from flow_mgr_full_hash_pass record.").iter().map(|v| v.as_f64().expect("Unable to transform flow_mgr_full_hash_pass u64.")).collect::<Vec<f64>>();

        for value in &mut flow_mgr_full_hash_pass {
            *value /= self.get_managers_stat(answers);
        }

        if debug {
            println!("flow_mgr_full_hash_pass:{:?}.", flow_mgr_full_hash_pass)
        }

        let uptime = self.get_uptime_stat(answers);
        let num_elements = (MIN_RUN /5) / WINDOWS;

        if ROB_REGRESSION == RobRegression::Huber {
            my_huber_regression(flow_mgr_full_hash_pass, uptime, FLOW_WINDOW, num_elements)
        }
        else {
            my_theil_sen_regression(flow_mgr_full_hash_pass, uptime, FLOW_WINDOW, num_elements)
        }
    }

    fn get_specific_cpu_usage(&self, answers: &Vec<Answer<'_>>, thread_name: &str) -> Vec<Thread> {
        let threads = self.get_thread_stat(answers);

        let mut cpu_usages: Vec<Thread> = Vec::new();

        for thread in threads {
            let my_thread: Thread = serde_json::from_value(thread.clone())
                .expect("Unable to deserialize");
            if my_thread.name.iter().any(|name| name.starts_with(thread_name)) {
                cpu_usages.push(my_thread);
            }
        }
        cpu_usages
    }

    fn get_workers(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let threads = self.get_thread_stat(answers);

        let mut workers: f64= 0.0;

        for thread in threads {
            let my_thread: Thread = serde_json::from_value(thread.clone())
                .expect("Unable to deserialize");
            if my_thread.name.iter().any(|name| name.starts_with("W")) {
                workers +=1.0;
            }
        }
        workers
    }

    fn get_new_workers(&self, answers: &Vec<Answer<'_>>) -> f64 {
        answers.iter().find(|a| a.key == &Keys::wrk_cpu_set).and_then(|d| d.value.as_array())
        .expect("wrk_cpu_set is not an array").len() as f64
    }

    fn free_memcap(&mut self, answers: &Vec<Answer<'_>>, changes: &Vec<MemcapChange>, debug: bool) -> bool {
        let mut total_used: u64 = 0;

        if !changes.iter().any(|c| c.keys == Keys::defrag_memcap) {
            let defrag_memcap_str = answers.iter().find(|a| a.key == &Keys::defrag_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get defrag_memcap as str.");
            total_used += Byte::parse_str(defrag_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert defrag_memcap to Bytes.");
        }
        if !changes.iter().any(|c| c.keys == Keys::stream_memcap) {
            let stream_memcap_str = answers.iter().find(|a| a.key == &Keys::stream_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get stream_memcap as str.");
            total_used += Byte::parse_str(stream_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert stream_memcap to Bytes.");
        }

        if !changes.iter().any(|c| c.keys == Keys::reassembly_memcap) {
            let reassembly_memcap_str = answers.iter().find(|a| a.key == &Keys::reassembly_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get reassembly_memcap as str.");
            total_used += Byte::parse_str(reassembly_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert reassembly_memcap to Bytes.");
        }

        if !changes.iter().any(|c| c.keys == Keys::ippair_memcap) {
            let ippair_memcap_str = answers.iter().find(|a| a.key == &Keys::ippair_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get ippair_memcap as str.");
            total_used += Byte::parse_str(ippair_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert ippair_memcap to Bytes.");
        }

        if !changes.iter().any(|c| c.keys == Keys::host_memcap) {
            let host_memcap_str  = answers.iter().find(|a| a.key == &Keys::host_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get host_memcap as str.");
            total_used += Byte::parse_str(host_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert host_memcap to Bytes.");
        }

        if !changes.iter().any(|c| c.keys == Keys::flow_memcap) {
            let flow_memcap_str  = answers.iter().find(|a| a.key == &Keys::flow_memcap).and_then(|d| d.value.as_str())
                .expect("Unable to get flow_memcap as str.");
            total_used += Byte::parse_str(flow_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert flow_memcap to Bytes.");
        }

        let max_memory_usage_str = answers.iter().find(|a| a.key == &Keys::max_memory_usage).and_then(|d| d.value.as_str())
            .expect("Unable to get max_memory_usage as str.");
        let max_memory_usage= Byte::parse_str(max_memory_usage_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert max_memory_usage_str to Bytes.");

        let max_pending_packets = if let Some(c) = changes.iter().find(|c| c.keys == Keys::max_pending_packets) {
            c.value
        } else {
            self.get_max_pending_packets(answers)
        };

        let default_packet_size = if let Some(c) = changes.iter().find(|c| c.keys == Keys::default_packet_size) {
            c.value
        } else {
            self.get_default_packet_size(answers)
        };

        let workers = self.get_new_workers(answers) as u64;

        total_used+= workers*(PACKET as u64 + default_packet_size)*max_pending_packets;

        total_used += changes.iter().map(|c| c.value).sum::<u64>();

        if debug  {
            println!("total_used: {total_used}, max_memory_usage: {max_memory_usage}");
        }

        total_used <= max_memory_usage
    }

    fn sweep_line_algorithm(&mut self, answers: &Vec<Answer<'_>>, min_slope: f64, debug: bool) -> BTreeMap<u64, Flow> {
        let mut flow_map: BTreeMap<u64, Flow> = Default::default();

        if let Some(flows) = answers.iter().find(|a| { a.key == &Keys::flow_set}).and_then(|a| a.value.as_object()) {
            for proto_flows in flows.values() {
                if let Some(proto_flows) = proto_flows.as_array() {
                    for proto_flow in proto_flows {
                        if let Some(proto_flow) = proto_flow.as_object() {
                            let start = proto_flow.get("start").and_then(|s| s.as_u64()).expect("Not able to find flow start in record.");
                            let mut end = proto_flow.get("end").and_then(|s| s.as_u64()).expect("Not able to find flow end in record.");
                            let flow_id = proto_flow.get("flow_id").and_then(|s| s.as_u64()).expect("Not able to find flow_id in record.");
                            let hash = self.get_hash_from_flow_id(flow_id);
                            let state = proto_flow.get("state").and_then(|s| s.as_str()).expect("Not able to find flow state in record.");
                            let proto = proto_flow.get("proto").and_then(|s| s.as_str()).expect("Not able to find flow protocol in record.");
                            let reason = Reason::new(proto_flow.get("reason").and_then(|s| s.as_str()).expect("Not able to find flow reason in record."));

                            match reason {
                                Reason::timeout | Reason::tcp_reuse | Reason::emergency   => {
                                    let timeout_manager_check = self.get_timeout_from_stats(answers, state, proto);
                                    end += timeout_manager_check + (1.0 / min_slope).ceil() as u64;
                                },
                                _ => {}
                            }

                            if start == end {
                                end +=1;
                            }

                            let flow =
                                flow_map
                                .entry(start)
                                .or_insert_with(Flow::default);

                            flow.flow_count += 1;
                            *flow.hashes.entry(hash).or_insert(0) += 1;

                            let flow =
                                flow_map
                                .entry(end)
                                .or_insert_with(Flow::default);


                            flow.flow_count -= 1;
                            *flow.hashes.entry(hash).or_insert(0) -= 1;

                        } else {
                            panic!("Unable to parse flow.");
                        }
                    }
                } else {
                    panic!("Unable to parse flows.");
                }
            }
        }
        else {
            panic!("Unable to parse flows.");
        }

        if debug {
            println!("flow_map:{:?}", flow_map)
        }
        flow_map
    }

    fn get_hash_from_flow_id(&self, flow_id: u64) -> u64 {
        let bitmask:u64 = 0x0000FFFF;
        let  mut flow_id = flow_id;
        flow_id &= bitmask;
        flow_id
    }

    fn get_timeout_from_stats(&self, answers: &Vec<Answer<'_>>, state: &str, proto: &str) -> u64 {
        let key = match  proto {
            "UDP" => {
                match state {
                    "new" => {"flow_timeouts_udp_new"},
                    "established" => {"flow_timeouts_udp_estab"},
                    "bypassed" => {"flow_timeouts_udp_bypass"},
                    "emergency-new" => {"flow_timeouts_udp_em_new"},
                    "emergency-established" => {"flow_timeouts_udp_em_estab"},
                    "emergency-bypassed" => {"flow_timeouts_udp_em_bypass"}
                    _ => panic!("Unable to convert key string slice.")
                }
            },
            "TCP" => {
                match state {
                    "new" => {"flow_timeouts_tcp_new"},
                    "established" => {"flow_timeouts_tcp_estab"},
                    "closed" => {"flow_timeouts_tcp_closed"},
                    "bypassed" => {"flow_timeouts_tcp_bypass"},
                    "emergency-new" => {"flow_timeouts_tcp_em_new"},
                    "emergency-established" => {"flow_timeouts_tcp_em_estab"},
                    "emergency-closed" => {"flow_timeouts_tcp_em_closed"},
                    "emergency-bypassed" => {"flow_timeouts_tcp_em_bypass"}
                    _ => panic!("Unable to convert key string slice.")
                }
            },
            "ICMP" => {
                match state {
                    "new" => {"flow_timeouts_icmp_new"},
                    "established" => {"flow_timeouts_icmp_estab"},
                    "bypassed" => {"flow_timeouts_icmp_bypass"},
                    "emergency-new" => {"flow_timeouts_icmp_em_new"},
                    "emergency-established" => {"flow_timeouts_icmp_em_estab"},
                    "emergency-bypassed" => {"flow_timeouts_icmp_em_bypass"}
                    _ => panic!("Unable to convert key string slice.")
                }
            },
            _ => {
                match state {
                    "new" => {"flow_timeouts_def_new"},
                    "established" => {"flow_timeouts_def_estab"},
                    "closed" => {"flow_timeouts_def_closed"},
                    "bypassed" => {"flow_timeouts_def_bypass"},
                    "emergency-new" => {"flow_timeouts_def_em_new"},
                    "emergency-established" => {"flow_timeouts_def_em_estab"},
                    "emergency-closed" => {"flow_timeouts_def_em_closed"},
                    "emergency-bypassed" => {"flow_timeouts_def_em_bypass"}
                    _ => panic!("Unable to convert key string slice.")
                }
            }
        };

        let new_key = Keys::new(key);
        answers.iter().find(|a| { a.key == &new_key}).expect(&format!("Unable to get {:?}", new_key)).value.as_u64().expect(&format!("Unable to transform {:?} to u64.", new_key))
    }
}
