use byte_unit::Byte;
use serde_json::Value;
use std::collections::HashMap;
use crate::{FLOW_WINDOW, MIN_RUN, PACKET, ROB_REGRESSION};
use crate::regression::{my_huber_regression, my_theil_sen_regression};
use crate::structures::{Analysis, Answer, Change, Keys, RobRegression, Thread, MemcapChange};

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

    fn get_thread_stat<'a>(&self, answers: &Vec<Answer<'a>>) -> &'a Vec<Value> {
         answers.iter().find(|h| h.key == &Keys::threads_stat).expect("Unable to get threads_stat.").value
            .as_array().expect("Unable to create array from mgr_cpu_usage record.")
    }

    fn get_flow_mgr_full_result(&self, answers: &Vec<Answer<'_>>, debug: bool) -> Vec<f64> {
        let flow_mgr_full_hash_pass = answers.iter().find(|h| h.key == &Keys::flow_mgr_full_hash_pass).expect("Unable to get flow_mgr_full_hash_pass.").value
            .as_array().expect("Unable to create array from flow_mgr_full_hash_pass record.").iter().map(|v| v.as_f64().expect("Unable to transform flow_mgr_full_hash_pass u64.")).collect::<Vec<f64>>();

        if debug {
            println!("flow_mgr_full_hash_pass:{:?}.", flow_mgr_full_hash_pass)
        }

        let uptime = self.get_uptime_stat(answers);
        let num_elements = MIN_RUN / FLOW_WINDOW ;

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

    fn get_workers(&mut self, answers: &Vec<Answer<'_>>) -> f64{
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

        let max_pending_packets = answers.iter().find(|a | a.key == &Keys::max_pending_packets).and_then(|a| a.value.as_u64())
            .expect("Unable to get max_pending_packets as u64.");

        let workers = self.get_workers(answers) as u64;

        total_used+= workers*PACKET*max_pending_packets;

        total_used += changes.iter().map(|c| c.value).sum::<u64>();

        if debug  {
            println!("total_used: {total_used}, max_memory_usage: {max_memory_usage}");
        }

        total_used <= max_memory_usage
    }
}
