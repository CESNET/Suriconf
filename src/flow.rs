use byte_unit::{Byte, UnitType};
use crate::structures::{Keys, ModuleResult, Analysis, Answer, Change, MemcapChange, Flow};
use crate::module::Module;
use std::collections::HashMap;
use serde_json::{Value};
use std::collections::BTreeMap;
use crate::{FLOW_WINDOW, MAX_AVG_RATIO, LOAD_FACTOR, MIN_AVG_RATIO, FLOW_OBJECT, SYNC_AVG, FLOW_BUCKET, FLOW_LOCAL_THREAD_MAX, MULTIPLIER};

#[derive(Debug)]
pub struct FlowModule {
    pub questions: HashMap<Keys, Value>, // changed
    pub flow_map: BTreeMap<u64, Flow>,
    pub debug: bool
}

#[derive(Debug, Default)]
pub struct Counter {
    pub flow_max: i64,
    pub flow_active: i64,
    pub current_max: i64,
    pub counter: u32
}

#[derive(Debug)]
pub struct SweepLineAlgo {
    pub time: u64,
    pub flows: i64
}

impl Module for FlowModule {
    fn new(analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::max_memory_usage,
            Keys::threads_stat,
            Keys::uptime,
            Keys::defrag_memcap, 
            Keys::stream_memcap, 
            Keys::reassembly_memcap, 
            Keys::ippair_memcap, 
            Keys::host_memcap,
            Keys::max_pending_packets, 
            Keys::flow_memcap,
            Keys::flow_memuse,
            Keys::flow_active,
            Keys::flow_hashsize,
            Keys::flow_prealloc,
            Keys::flow_managers,
            Keys::flow_recyclers,
            Keys::flow_set,
            Keys::flow_mgr_full_hash_pass,
            Keys::flow_wrk_spare_sync_avg,
            Keys::flow_wrk_spare_sync_empty,
            Keys::flow_wrk_spare_sync_incomplete,
            Keys::flow_timeouts_def_new,
            Keys::flow_timeouts_def_estab,
            Keys::flow_timeouts_def_closed,
            Keys::flow_timeouts_def_bypass,
            Keys::flow_timeouts_def_em_new,
            Keys::flow_timeouts_def_em_estab,
            Keys::flow_timeouts_def_em_closed,
            Keys::flow_timeouts_def_em_bypass,
            Keys::flow_timeouts_tcp_new,
            Keys::flow_timeouts_tcp_estab,
            Keys::flow_timeouts_tcp_closed,
            Keys::flow_timeouts_tcp_bypass,
            Keys::flow_timeouts_tcp_em_new,
            Keys::flow_timeouts_tcp_em_estab,
            Keys::flow_timeouts_tcp_em_closed,
            Keys::flow_timeouts_tcp_em_bypass,
            Keys::flow_timeouts_udp_new,
            Keys::flow_timeouts_udp_estab,
            Keys::flow_timeouts_udp_bypass,
            Keys::flow_timeouts_udp_em_new,
            Keys::flow_timeouts_udp_em_estab,
            Keys::flow_timeouts_udp_em_bypass,
            Keys::flow_timeouts_icmp_new,
            Keys::flow_timeouts_icmp_estab,
            Keys::flow_timeouts_icmp_bypass,
            Keys::flow_timeouts_icmp_em_new,
            Keys::flow_timeouts_icmp_em_estab,
            Keys::flow_timeouts_icmp_em_bypass, 
            Keys::max_pending_packets,
            Keys::default_packet_size, 
            Keys::wrk_cpu_set
        ];

        let questions: HashMap<Keys, Value> =
            keys.into_iter()
                .map(|k| (k, Value::Null))
                .collect();

        Self { questions, flow_map: BTreeMap::new(), debug }
    }

    fn questions(&self) -> &HashMap<Keys, Value> {
        &self.questions
    }

    fn main(&mut self, answers: &Vec<Answer<'_>>) -> Vec<Change> {
        if self.debug {
            println!("Suricata max flow active: {}", self.get_suri_max_flow_active_stat(answers));
        }
        let flow_mgr_full_result = self.get_flow_mgr_full_result(answers, self.debug);
        let min_slope = flow_mgr_full_result.iter().min_by(|a, b| a.partial_cmp(b).expect("Unable to compare flow_mgr_full_result.")).expect("Unable to find manager minimum slope.");
        if self.debug {
            println!("Minimal slope: {min_slope}");
        }
        self.flow_map = self.sweep_line_algorithm(answers, *min_slope, self.debug);

         match self.get_prealloc(answers) {
             ModuleResult::Up|ModuleResult::Down => {
            *self.questions.get_mut(&Keys::flow_prealloc).expect("Unable to get flow_prealloc from intern table.") = Value::Number((self.get_suri_max_flow_active_stat(answers)/2).into());
            },
             ModuleResult::Ok => {}
        };

       match self.get_flow_hash_size(answers) {
           ModuleResult::Up | ModuleResult::Down =>  {
               let max_flow_active = self.get_max_flow_active();
               *self.questions.get_mut(&Keys::flow_hashsize).expect("Unable to get flow_hashsize from intern table.") = Value::Number(max_flow_active.next_power_of_two().into());
           },
           ModuleResult::Ok  => {}
       }

        let changes : Vec<MemcapChange> = vec![MemcapChange {
            keys: Keys::flow_memcap, 
            value:self.get_flow_memcap(answers) as u64
        }];
        
        if self.free_memcap(answers, &changes, self.debug) {
            let flow_memcap = changes.iter().find(|a| a.keys == Keys::flow_memcap).expect("Unable to get flow_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::flow_memcap).expect("Unable to get flow_memcap from intern table.") = Value::String(Byte::from_u64(flow_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());    
        }
        else {
            panic!("Unable to set flow_memcap, not enough memory. Memory check failed. Check max_memory_usage.")
        }
        
        Change::collect_changes(&self.questions)
    }

}

impl FlowModule {
    fn get_prealloc(&self, answers: &Vec<Answer<'_>>)-> ModuleResult {
        let sync_avg = answers.iter().find(|a| a.key == &Keys::flow_wrk_spare_sync_avg).expect("Unable to get flow worker spare sync average.");
        let sync_incomplete = answers.iter().find(|a| a.key == &Keys::flow_wrk_spare_sync_incomplete).expect("Unable to get flow worker spare incompletes.");
        let sync_empty = answers.iter().find(|a| a.key == &Keys::flow_wrk_spare_sync_empty).expect("Unable to get flow worker spare empty.");

        if sync_incomplete.value.as_array().expect("Unable to create vector from sync_incomplete").last().and_then(|a| a.as_u64()).expect("Unable to get last value as u64.") > 0 {
            return ModuleResult::Up
        }

        if sync_empty.value.as_array().expect("Unable to create vector from sync_empty.").last().and_then(|a| a.as_u64()).expect("Unable to get last value as u64.") > 0 {
            return ModuleResult::Up
        }
        if sync_avg.value.as_array().map(|arr| arr.iter().filter_map(|v| v.as_u64()).sum::<u64>()).expect("Unable to get values for sync_avg.") < SYNC_AVG {
            return ModuleResult::Up
        }

        if self.get_prealloc_stat(answers) > self.get_suri_max_flow_active_stat(answers)/2  {
            return ModuleResult::Down
        }
        ModuleResult::Ok
    }

    fn get_max_flow_active(&self) -> u64 {
        let mut counter: Counter = Default::default();
        for time in  self.flow_map.iter() {
            counter.flow_active += time.1.flow_count;
            if counter.flow_active > counter.flow_max {
                counter.flow_max = counter.flow_active;
            }
        }
        if self.debug {
            println!("My flow max: {}", counter.flow_max);
        }
        counter.flow_max as u64
    }

    fn get_suri_max_flow_active_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
         answers.iter().find(|a| a.key == &Keys::flow_active).expect("Unable to get flow active maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get flow active maximum.")
    }

    fn get_prealloc_stat(&self, answers: &Vec<Answer<'_>>) -> u64{
         answers.iter().find(|a| a.key == &Keys::flow_prealloc).expect("Unable to get prealloc.").value.as_u64().expect("Unable to get prealloc as u64.")
    }

    fn get_flow_hash_size_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
        answers.iter().find(|h| h.key == &Keys::flow_hashsize).and_then(|h| h.value.as_f64()).expect("Flow hashsize cannot be found.")
    }

    fn get_flow_hash_size(&mut self, answers: &Vec<Answer<'_>>) -> ModuleResult {
        let mut current_queues: BTreeMap<u64, i64> = BTreeMap::new(); // hash, count(cumulative)
        let mut current_average: i64 = 0;
        let mut counter: Counter = Default::default();
        let flow_hash_size= self.get_flow_hash_size_stat(answers);

        for time in  self.flow_map.iter() {
            counter.flow_active += time.1.flow_count;
            if counter.flow_active > counter.flow_max {
                counter.flow_max = counter.flow_active;
            }
            counter.counter+=1;

            for flow in &time.1.hashes {
                let v = current_queues.entry(*flow.0).or_insert(0);
                *v += *flow.1;
                if (*v > counter.current_max) {
                    counter.current_max = *v;
                }
            }

            for (_, value) in &current_queues {
                current_average += *value;
            }

            if counter.counter == FLOW_WINDOW as u32 {
                current_average /= (flow_hash_size*FLOW_WINDOW as f64) as i64;

                if self.debug {
                    println!("flow_hash_size: {flow_hash_size}, current_row_average: {current_average}, current_row_max: {}", counter.current_max);
                }

                if counter.current_max != 0 {
                    if (current_average/counter.current_max) >= MAX_AVG_RATIO {
                        return ModuleResult::Up
                    }
                }

                if self.get_load_factor(counter.flow_active, flow_hash_size) >= LOAD_FACTOR {
                    return ModuleResult::Up
                }

                current_average = 0;
                for (_, value) in &current_queues {
                        current_average += *value;
                }

                counter.current_max = 0;
                counter.counter = 0;
            }
        }
        if self.get_load_factor(counter.flow_max, flow_hash_size) < MIN_AVG_RATIO {
            return ModuleResult::Down
        }

        ModuleResult::Ok
    }

    fn get_flow_memcap(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_flow_active = self.get_suri_max_flow_active_stat(answers) as f64;
        let workers: f64=  self.get_new_workers(answers);

        if self.debug {
            println!("workers: {workers}");
        }

        let hash_size =
            match self.questions.get(&Keys::flow_hashsize) {
                Some(Value::Null) => {
                    self.get_flow_hash_size_stat(answers)
                },
                Some(value) => {
                    value.as_f64().expect("Unable to get flow hash_size as f64.")
                }
                _ => {
                    panic!("Unable to get value for flow hash_size.")
                }
            };

        let prealloc=
            match self.questions.get(&Keys::flow_prealloc) {
                Some(Value::Null) => {
                    self.get_prealloc_stat(answers) as f64
                },
                Some(value) => {
                    value.as_f64().expect("Unable to get flow_prealloc as f64.")
                }
                _ => {
                    panic!("Unable to get value for flow_prealloc.")
                }
            };

        hash_size*FLOW_BUCKET+(max_flow_active+prealloc*MULTIPLIER+workers*FLOW_LOCAL_THREAD_MAX)*FLOW_OBJECT
    }
}