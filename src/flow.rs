use crate::structures::{Module, Keys, ModuleResult, RobRegression, Analysis, Thread, Answer, Change, Reason};
use std::collections::HashMap;
use serde_json::{Value};
use std::collections::BTreeMap;
use crate::{FLOW_WINDOW, MAX_AVG_RATIO, LOAD_FACTOR, MIN_AVG_RATIO, FLOW_OBJECT, SYNC_AVG, FLOW_BUCKET, FLOW_LOCAL_THREAD_MAX, ROB_REGRESSION, WINDOWS, HUBER_THRESHOLD, CPU_USAGE_MAX, MIN_RUN, MANAGER_SLOPE};
use crate::regression::{my_huber_regression, my_theil_sen_regression};

#[derive(Debug)]
pub struct FlowModule {
    pub questions: HashMap<Keys, Value>, // changed
    pub flow_map: BTreeMap<u64, Flow>,
    pub debug: bool
}

#[derive(Debug, Default)]
pub struct Flow {
    pub flow_count: i64,
    pub hashes: BTreeMap<u64, i64>, // hash, count
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

#[derive(Debug, Default)]
pub struct RecyclerUp {
    pub queue_growth: f64,
    pub now_in_queue_avg: f64,
    pub now_recycled_avg: f64
}

impl Module for FlowModule {
    fn new(analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::max_memory_usage,
            Keys::max_cpu_usage_vec,
            Keys::threads_stat,
            Keys::uptime,
            Keys::flow_memcap,
            Keys::flow_memuse,
            Keys::flow_active,
            Keys::flow_hashsize,
            Keys::flow_prealloc,
            Keys::flow_managers,
            Keys::flow_recyclers,
            Keys::flow_set,
            Keys::flow_rc_queue_avg,
            Keys::flow_rc_recycled,
            Keys::flow_mgr_full_hash_pass,
            Keys::flow_wrk_spare_sync_avg,
            Keys::flow_wrk_spare_sync_empty,
            Keys::flow_wrk_spare_sync_incomplete,
            Keys::flow_emerg_mode_entered,
            Keys::flow_emerg_mode_over,
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
            Keys::flow_timeouts_icmp_em_bypass
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
        let mut min_slope :f64 = f64::MAX;

        match self.get_manager_count(answers, &mut min_slope) {
            (ModuleResult::Up, Some(new_managers)) => {
                *self.questions.get_mut(&Keys::flow_managers).expect("Unable to get flow_managers from intern table.") = Value::Number(new_managers.into());
            },
            _ => {}
        }

        if self.debug {
            println!("Minimal manager slope: {min_slope}.");
            println!("Suricata max flow active: {}", self.get_suri_max_flow_active_stat(answers));
        }

        match self.get_recycler_count(answers) {
            (ModuleResult::Up, Some(new_recyclers)) => {
                *self.questions.get_mut(&Keys::flow_recyclers).expect("Unable to get flow_recyclers from intern table.") = Value::Number(new_recyclers.into());
            },
            _ => {}

        }

        self.sweep_line_algorithm(answers, min_slope);

         match self.get_prealloc(answers) {
             ModuleResult::Up|ModuleResult::Down => {
            *self.questions.get_mut(&Keys::flow_prealloc).expect("Unable to get flow_prealloc from intern table.") = Value::Number((self.get_suri_max_flow_active_stat(answers)/2).into());
            },
             ModuleResult::Ok => {}
        };

       match  self.get_flow_hash_size(answers) {
           ModuleResult::Up | ModuleResult::Down =>  {
               let max_flow_active = self.get_max_flow_active();
               *self.questions.get_mut(&Keys::flow_hashsize).expect("Unable to get flow_hashsize from intern table.") = Value::Number(max_flow_active.next_power_of_two().into());
           },
           ModuleResult::Ok  => {}
       }

        *self.questions.get_mut(&Keys::flow_memcap).expect("Unable to get flow_memcap from intern table.") = Value::Number((self.get_flow_memcap(answers) as u64).into());

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

    fn get_uptime_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        *answers.iter().find(|h| h.key == &Keys::uptime).expect("Unable to get uptime.").value
        .as_array().expect("Unable to create array from uptime record.").iter().map(|a| a.as_u64().expect("Unable to transform uptime to u64.")).collect::<Vec<u64>>().last().expect("Unable to get last uptime.")
    }

    fn get_recycled_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<u64> {
        answers.iter().find(|h| h.key == &Keys::flow_rc_recycled).expect("Unable to get flow_rc_recycled.").value
        .as_array().expect("Unable to create array from flow_rc_recycled record.").iter().map(|a| a.as_u64().expect("Unable to transform flow_rc_recycled to u64.")).collect::<Vec<u64>>()
    }

    fn get_load_factor(&self, flow_active: i64, flow_hash_size: f64) -> f64  {
        flow_active as f64 / flow_hash_size
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

    fn get_hash_from_flow_id(&self, flow_id: u64) -> u64 {
        let bitmask:u64 = 0x0000FFFF;
        let  mut flow_id = flow_id;
        flow_id &= bitmask;
        flow_id
    }

    fn get_specific_cpu_usage(&self, answers: &Vec<Answer<'_>>, thread_name: &str) -> Vec<Thread> {
        let threads = answers.iter().find(|h| h.key == &Keys::threads_stat).expect("Unable to get threads_stat.").value
            .as_array().expect("Unable to create array from mgr_cpu_usage record.");

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

    fn get_manager_count(&self, answers: &Vec<Answer<'_>>, min_slope: &mut f64) -> (ModuleResult, Option<u64>) {
        let flow_mgr_full_hash_pass = answers.iter().find(|h| h.key == &Keys::flow_mgr_full_hash_pass).expect("Unable to get flow_mgr_full_hash_pass.").value
            .as_array().expect("Unable to create array from flow_mgr_full_hash_pass record.").iter().map(|v| v.as_f64().expect("Unable to transform flow_mgr_full_hash_pass u64.")).collect::<Vec<f64>>();

        if self.debug {
            println!("flow_mgr_full_hash_pass: {:?}", flow_mgr_full_hash_pass);
        }

        let uptime = self.get_uptime_stat(answers);
        let num_elements = MIN_RUN / FLOW_WINDOW ;

        let flow_mgr_full_result: Vec<f64> =
        if ROB_REGRESSION == RobRegression::Huber {
            my_huber_regression(flow_mgr_full_hash_pass, uptime, FLOW_WINDOW, num_elements)

        }
        else {
            my_theil_sen_regression(flow_mgr_full_hash_pass, uptime, FLOW_WINDOW, num_elements)

        };

        let mgr_cpu_usages: Vec<Thread> = self.get_specific_cpu_usage(answers, "FM");

        if self.debug {
            println!("flow_mgr_full_result: {:?}, mgr_cpu_usages: {:?}",  flow_mgr_full_result, mgr_cpu_usages);
        }

        let mut counter = 0;
        let mut sm_counter = 0;
        let mut avg_cpu_usage: Vec<f32> = Vec::new();
        let mut current_flow_mgr_full_result: Vec<f64>;
        let mut up=  true;
        let mut slope_vector: Vec<f64> = Vec::new();
        let mut tmp_slope_vector: Vec<f64> = Vec::new();

        loop {

            for i in 0..WINDOWS {
                for mgr_cpu_usage in &mgr_cpu_usages {
                    let avg: f32 = mgr_cpu_usage.cpu_usage[((counter*WINDOWS+i)*num_elements) as usize..(((counter*WINDOWS+1)+i)*num_elements) as usize]
                        .iter().sum::<f32>() / (num_elements as f32);
                    avg_cpu_usage.push(avg);
                }
            }

            current_flow_mgr_full_result = flow_mgr_full_result[(counter*WINDOWS) as usize..((counter+1)*WINDOWS) as usize].to_vec();


            for flow_mgr_full_result in &current_flow_mgr_full_result {
                let avg: f32 = avg_cpu_usage[(sm_counter * (avg_cpu_usage.len()/WINDOWS as usize)) ..
                    ((sm_counter + 1) * (avg_cpu_usage.len()/WINDOWS as usize))]
                    .iter().sum::<f32>() / (avg_cpu_usage.len()/WINDOWS as usize) as f32;
                sm_counter+=1;

                if flow_mgr_full_result < min_slope {
                    *min_slope = *flow_mgr_full_result;
                }

                if flow_mgr_full_result < &MANAGER_SLOPE {
                    tmp_slope_vector.push(*flow_mgr_full_result);
                    up &= true;
                }
                else {
                    up &= false;
                    break;
                }

                if avg > CPU_USAGE_MAX {
                    up &= true;
                }
                else {
                    up &= false;
                    break;
                }
            }
            sm_counter=0;

            if up {
                slope_vector.push(tmp_slope_vector.iter().sum::<f64>() / tmp_slope_vector.len() as f64);
            }

            if current_flow_mgr_full_result.last() == flow_mgr_full_result.last() {
                break;
            }
            counter +=1;
            current_flow_mgr_full_result.clear();
            avg_cpu_usage.clear();
            tmp_slope_vector.clear();
        }

        if !slope_vector.is_empty() {
            let mgr_power = slope_vector.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).expect("Unable to find mgr_power minimum.");
            let managers = self.get_managers_stat(answers);
            let one_mgr_power = mgr_power/managers;
            let managers = (MANAGER_SLOPE/one_mgr_power).ceil() as u64;
            return (ModuleResult::Up, Some(managers));
        }
        (ModuleResult::Ok, None)
    }

    fn get_recycler_count(&self, answers: &Vec<Answer<'_>>) -> (ModuleResult, Option<u64>) {

        let in_queue = self.get_flows_in_queue(answers);
        let recycled = self.get_recycled_stat(answers);
        let uptime = self.get_uptime_stat(answers);
        let num_elements = MIN_RUN / FLOW_WINDOW ;

        let in_queue_result: Vec<f64> =
            if ROB_REGRESSION == RobRegression::Huber {
                my_huber_regression(in_queue.clone(), uptime, FLOW_WINDOW, num_elements)
            }
            else {
                my_theil_sen_regression(in_queue.clone(), uptime, FLOW_WINDOW, num_elements)
            };

        let rc_cpu_usages: Vec<Thread> = self.get_specific_cpu_usage(answers, "FR");

        let mut counter = 0;
        let mut sm_counter = 0;
        let mut avg_cpu_usage: Vec<f32> = Vec::new();
        let mut current_in_queue_result: Vec<f64>;
        let mut up=  true;
        let mut slope_vector: Vec<RecyclerUp> = Vec::new();
        let mut tmp_slope_vector: Vec<f64> = Vec::new();

        loop {

            for i in 0..WINDOWS {
                for rc_cpu_usage in &rc_cpu_usages {
                    let avg: f32 = rc_cpu_usage.cpu_usage[((counter*WINDOWS+i)*num_elements) as usize..(((counter*WINDOWS+1)+i)*num_elements) as usize]
                        .iter().sum::<f32>() / (num_elements as f32);
                    avg_cpu_usage.push(avg);
                }
            }

            current_in_queue_result = in_queue_result[(counter*WINDOWS) as usize..((counter+1)*WINDOWS) as usize].to_vec();


            for current_queue in &current_in_queue_result {
                let avg: f32 = avg_cpu_usage[(sm_counter * (avg_cpu_usage.len()/WINDOWS as usize)) ..
                    ((sm_counter + 1) * (avg_cpu_usage.len()/WINDOWS as usize))]
                    .iter().sum::<f32>() / (avg_cpu_usage.len()/WINDOWS as usize) as f32;
                sm_counter+=1;

                if current_queue > &HUBER_THRESHOLD {
                    tmp_slope_vector.push(*current_queue);
                    up &= true;
                }
                else {
                    up &= false;
                    break;
                }

                if avg > CPU_USAGE_MAX {
                    up &= true;
                }
                else {
                    up &= false;
                    break;
                }
            }
            sm_counter=0;

            if up {
                let mut recycler_up: RecyclerUp = Default::default();
                recycler_up.queue_growth = tmp_slope_vector.iter().sum::<f64>() / tmp_slope_vector.len() as f64;
                let now_in_queue = in_queue[(counter*WINDOWS*num_elements) as usize ..((counter+WINDOWS)*WINDOWS*num_elements) as usize].to_vec();
                let now_recycled = recycled[(counter*WINDOWS*num_elements) as usize..((counter+WINDOWS)*WINDOWS*num_elements) as usize].to_vec();
                let now_recycled: Vec<f64> = now_recycled.windows(2).map(|w| (w[1] - w[0]) as f64).collect();

                recycler_up.now_in_queue_avg = now_in_queue.iter().sum::<f64>() / now_in_queue.len() as f64;
                recycler_up.now_recycled_avg = now_recycled.iter().sum::<f64>() / now_recycled.len() as f64;
                slope_vector.push(recycler_up);
            }

            if current_in_queue_result.last() == in_queue_result.last() {
                break;
            }
            counter +=1;
            current_in_queue_result.clear();
            avg_cpu_usage.clear();
            tmp_slope_vector.clear();
        }

        if !slope_vector.is_empty() {
            let recycler_up = slope_vector.iter().max_by(|a, b| a.queue_growth.partial_cmp(&b.queue_growth).unwrap()).expect("Unable to find rc_power maximum.");
            let recyclers = self.get_recyclers_stat(answers);
            let one_recycler_power = recyclers / recycler_up.now_recycled_avg;
            let has_to_clean = recycler_up.now_in_queue_avg*recycler_up.queue_growth;
            let recyclers = (has_to_clean / one_recycler_power).ceil() as u64;
            return (ModuleResult::Up, Some(recyclers));
        }

        (ModuleResult::Ok, None)
    }

    fn get_recyclers_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
         answers.iter().find(|h| h.key == &Keys::flow_recyclers).expect("Unable to get flow_managers.").value.as_f64().expect("Unable to transform flow_managers to f64.")
    }

    fn get_managers_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
        answers.iter().find(|h| h.key == &Keys::flow_managers).expect("Unable to get flow_managers.").value.as_f64().expect("Unable to transform flow_managers to u64.")
    }

    fn get_flows_in_queue(&self, answers: &Vec<Answer<'_>>) -> Vec<f64> {
        let recycled_avg = answers.iter().find(|h| h.key == &Keys::flow_rc_queue_avg).expect("Unable to get flow_rc_queue_avg.").value
            .as_array().expect("Unable to create array from flow_rc_queue_avg record.").iter().map(|a| a.as_u64().expect("Unable to transform flow_rc_queue_avg u64.")).collect::<Vec<u64>>();

        if self.debug {
            println!("recycled_avg: {:?}", recycled_avg);
        }

        let mut in_queue: Vec<f64> = Vec::new();

        let mut counter = 0;
        let mut sum = 0;

        for record in recycled_avg.iter() {
            counter += 1;

            let queue_size = record * counter - sum;

            if self.debug {
                println!("queue_size: {queue_size}.");
            }

            sum += queue_size;

            in_queue.push(queue_size as f64);
        }
        in_queue
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
    
    fn sweep_line_algorithm(&mut self, answers: &Vec<Answer<'_>>, min_slope: f64) {
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

                            let flow = self
                                .flow_map
                                .entry(start)
                                .or_insert_with(Flow::default);

                            flow.flow_count += 1;
                            *flow.hashes.entry(hash).or_insert(0) += 1;

                            let flow = self
                                .flow_map
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

        if self.debug {
            println!("flow_map:{:?}", self.flow_map)
        }
    }

    fn get_flow_memcap(&mut self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_flow_active = self.get_suri_max_flow_active_stat(answers) as f64;
        let mut wrk_cpu_set_len = answers.iter().find(|a| { a.key == &Keys::max_cpu_usage_vec}).expect("Unable to get workers cpu set.")
            .value.as_array().map(|a| a.len()).expect("Unable to compute the len of worker cpu set.") as f64;

        let flow_recyclers =  self.questions.get_mut(&Keys::flow_recyclers).expect("Unable to get flow_recyclers from intern table.").clone();
        let flow_managers = self.questions.get_mut(&Keys::flow_managers).expect("Unable to get flow_managers from intern table.").clone();
        let mut management = 0.0;

        if flow_recyclers == Value::Null {
            management += answers.iter().find(|a| {a.key == &Keys::flow_recyclers}).expect("Unable to get flow_recyclers.").value.as_f64().expect("Unable to get  flow_recyclers as f64.");
        }
        else {
            management += flow_recyclers.as_f64().expect("Unable to transform flow_recyclers to u64.")
        }

        if flow_managers == Value::Null {
            management += answers.iter().find(|a| {a.key == &Keys::flow_managers}).expect("Unable to get flow_managers.").value.as_f64().expect("Unable to get  flow_managers as f64.");
        }
        else {
            management += flow_managers.as_f64().expect("Unable to transform flow_managers to u64.")
        }

        wrk_cpu_set_len = wrk_cpu_set_len - management;

        let hash_size = answers.iter().find(|a| {a.key == &Keys::flow_hashsize}).expect("Unable to get hash size of Flow table.").value.as_f64().expect("Unable to get hash_size as f64.");
        let prealloc=
            match self.questions.get_mut(&Keys::flow_prealloc) {
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

        hash_size*FLOW_BUCKET+(max_flow_active+prealloc*1.2+wrk_cpu_set_len*FLOW_LOCAL_THREAD_MAX)*FLOW_OBJECT
    }
}