/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file represents a Flow threads module.
*/

use crate::structures::{Keys, ModuleResult, RobRegression, Analysis, Thread, Answer, Change};
use crate::module::Module;
use std::collections::{HashMap};
use serde_json::{Value};
use crate::{FLOW_WINDOW, ROB_REGRESSION, WINDOWS, HUBER_THRESHOLD, CPU_USAGE_MAX, MIN_RUN, MANAGER_SLOPE};
use crate::regression::{my_huber_regression, my_theil_sen_regression};

#[derive(Debug)]
pub struct FlowThreadsModule {
    pub questions: HashMap<Keys, Value>, // changed
    pub debug: bool
}

#[derive(Debug, Default)]
pub struct RecyclerUp {
    pub queue_growth: f64,
    pub now_in_queue_avg: f64,
    pub now_recycled_avg: f64
}

impl Module for FlowThreadsModule {
    fn new(_analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::flow_recyclers,
            Keys::flow_managers,
            Keys::uptime,
            Keys::flow_rc_queue_avg,
            Keys::flow_rc_recycled,
            Keys::threads_stat,
            Keys::flow_mgr_full_hash_pass,
            Keys::wrk_cpu_set
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

    fn main(&mut self, answers: &Vec<Answer<'_>>, ) -> Vec<Change> {
        match self.get_manager_count(answers) {
            (ModuleResult::Up, Some(new_managers)) => {
                *self.questions.get_mut(&Keys::flow_managers).expect("Unable to get flow_managers from intern table.") = Value::Number(new_managers.into());
            },
            _ => {}
        }

        match self.get_recycler_count(answers) {
            (ModuleResult::Up, Some(new_recyclers)) => {
                *self.questions.get_mut(&Keys::flow_recyclers).expect("Unable to get flow_recyclers from intern table.") = Value::Number(new_recyclers.into());
            },
            _ => {}
        }
        Change::collect_changes(&self.questions)
    }
    }

impl  FlowThreadsModule {
    fn get_recycler_count(&self, answers: &Vec<Answer<'_>>) -> (ModuleResult, Option<u64>) {

        let in_queue = self.get_flows_in_queue(answers);
        let recycled = self.get_recycled_stat(answers);
        let uptime = self.get_uptime_stat(answers);
        let num_elements = (MIN_RUN/5) / WINDOWS;

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

            let last_three = in_queue_result.iter().rev().take(3).collect::<Vec<_>>();
            if last_three.contains(&current_in_queue_result.last().expect("Unable to get last element from current_in_queue_result vector."))  {
                break;
            }

            counter +=1;
            current_in_queue_result.clear();
            avg_cpu_usage.clear();
            tmp_slope_vector.clear();
        }

        if !slope_vector.is_empty() {
            let recycler_up = slope_vector.iter().max_by(|a, b| a.queue_growth.partial_cmp(&b.queue_growth).expect("Unable to compare rc_power.")).expect("Unable to find rc_power maximum.");
            let recyclers = self.get_recyclers_stat(answers);
            let one_recycler_power = recyclers / recycler_up.now_recycled_avg;
            let has_to_clean = recycler_up.now_in_queue_avg*recycler_up.queue_growth;
            let recyclers = (has_to_clean / one_recycler_power).ceil() as u64;
            return (ModuleResult::Up, Some(recyclers));
        }

        (ModuleResult::Ok, None)
    }

    fn get_manager_count(&self, answers: &Vec<Answer<'_>>) -> (ModuleResult, Option<u64>) {
        let num_elements = (MIN_RUN / 5) / WINDOWS ;
        let flow_mgr_full_result  = self.get_flow_mgr_full_result(answers, self.debug);
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

            let last_three = flow_mgr_full_result.iter().rev().take(3).collect::<Vec<_>>();
            if last_three.contains(&current_flow_mgr_full_result.last().expect("Unable to get last element from current_flow_mgr_full_result vector."))  {
                break;
            }

            counter +=1;
            current_flow_mgr_full_result.clear();
            avg_cpu_usage.clear();
            tmp_slope_vector.clear();
        }

        if !slope_vector.is_empty() {
            let mgr_power = slope_vector.iter().min_by(|a, b| a.partial_cmp(b).expect("Unable to compare mgr_power.")).expect("Unable to find mgr_power minimum.");
            let managers = self.get_managers_stat(answers);
            let one_mgr_power = mgr_power/managers;
            let managers = (MANAGER_SLOPE/one_mgr_power).ceil() as u64;
            return (ModuleResult::Up, Some(managers));
        }
        (ModuleResult::Ok, None)
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

            if self.debug {
                println!("record: {record}, counter: {counter}, sum: {sum}");
            }

            let queue_size = (record * counter).saturating_sub(sum);

            if self.debug {
                println!("queue_size: {queue_size}.");
            }

            sum += queue_size;

            in_queue.push(queue_size as f64);
        }
        in_queue
    }

    fn get_recycled_stat(&self, answers: &Vec<Answer<'_>>) -> Vec<u64> {
        answers.iter().find(|h| h.key == &Keys::flow_rc_recycled).expect("Unable to get flow_rc_recycled.").value
            .as_array().expect("Unable to create array from flow_rc_recycled record.").iter().map(|a| a.as_u64().expect("Unable to transform flow_rc_recycled to u64.")).collect::<Vec<u64>>()
    }
}