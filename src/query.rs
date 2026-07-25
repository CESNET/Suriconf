/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file represents a Query and Execute stage.
It invokes modules and stores their configurations.
*/

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::{PathBuf};
use crate::structures::{Keys, FileNames, create_module, JsonVar, Answer, Change, Modules};
use strum::IntoEnumIterator;
use crate::yaml::{Suriconf};
use serde_json::{Value, Number};
use std::fs;
use crate::{yaml};
use crate::json::{find_in_json_with_path_mut, find_in_json_with_path_ref, json_to_value, open_json};

#[derive(Debug)]
pub struct Resources {
    pub suri_configuration: PathBuf,
    pub suriconf_struct: Suriconf,
    pub suriconf: PathBuf,
    pub preconfiguration: PathBuf,
    pub tables: Vec<FileQuestionStructure>,
    pub json_var: JsonVar, //changes in jsons
    pub debug: bool
}
#[derive(Default, Debug)]
pub struct Jsons {
    suricata: Value,
    suriconf: Value,
    preconf: Value
}

impl Jsons {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn open_jsons(&mut self, resources: &Resources) -> Result<(), Box<dyn std::error::Error>> {
        for file_name in FileNames::iter() {
            let json = match file_name {
                FileNames::suricata | FileNames::suriconf => {
                    let yaml = match yaml::open_yaml(self.path(resources, &file_name)) {
                        Ok(yaml) => {yaml},
                        Err(e) => {return Err(Box::from(format!("Unable to parse yaml file to value. {e}")))}
                    };
                    yaml::yaml_to_json(yaml)
                },
                FileNames::preconf => {
                    let json = match open_json(self.path(resources, &file_name)) {
                        Ok(json) => {json},
                        Err(e) => {return Err(Box::from(format!("Unable to parse json file to value. {e}")))}
                    };

                    match json_to_value(json) {
                        Ok(json) => {json},
                        Err(e) => {return Err(Box::from(format!("Unable to parse json file to value. {e}")))}
                    }
                }
            };
            match file_name {
                FileNames::suricata => self.suricata = json,
                FileNames::suriconf => self.suriconf = json,
                FileNames::preconf => self.preconf = json,
            }
        }
        Ok(())
    }
        pub fn path<'a>(&self, resources: &'a Resources, file_name: &FileNames) -> &'a PathBuf {
            let resource = match file_name  {
                FileNames::suricata => &resources.suri_configuration,
                FileNames::suriconf => &resources.suriconf,
                FileNames::preconf  => &resources.preconfiguration,
            };
            resource
        }
        pub fn get_answer(&mut self, file_name: &FileNames, file_path: &str) -> Value {
            let json = match file_name {
                FileNames::suricata => {&mut self.suricata},
                FileNames::preconf => {&mut self.preconf},
                FileNames::suriconf => {&mut self.suriconf}
            };

            find_in_json_with_path_ref(json, file_path)

        }
}

#[derive(Debug)]
pub struct FileQuestionStructure {
    pub file_name: FileNames,
    pub questions: HashMap<Keys, QuestionPart>
}

impl FileQuestionStructure {
    pub fn new(file_name: FileNames) -> Self {
        Self {
            file_name,
            questions: HashMap::new()
        }
    }
}
#[derive(Debug)]
pub struct QuestionPart {
    pub file_path: String,
    pub value: Value,
    pub changed: bool
}
impl Resources {
    pub fn new(suri_configuration: PathBuf, suriconf_struct: Suriconf, suriconf: PathBuf, preconfiguration: PathBuf, json_var: JsonVar, debug: bool) -> Self {
        Self {
            suri_configuration,
            suriconf_struct,
            suriconf,
            preconfiguration,
            tables: Vec::new(),
            json_var,
            debug
        }
    }

    pub fn main_query(&mut self) {

        for file_name in FileNames::iter() {
            let mut file_table = FileQuestionStructure::new(file_name);
            let path_to_query_file = PathBuf::from("./query")
                .join(format!("{}.json", file_name.to_string()));

            let json = match open_json(&path_to_query_file) {
                Ok(json) => { json },
                Err(e) => { panic!("{e}.") }
            };

            let json = match json_to_value(json) {
                Ok(json) => { json },
                Err(e) => { panic!("{e}.") }
            };

            if let Some(questions) = json.get("questions").and_then(|q| q.as_object()) {
                for (key, value) in questions {
                    if let Some(Value::String(s)) = value.get("path_to_value") {
                    let key = Keys::new(key);

                        let question_part = QuestionPart {
                            file_path: s.clone(),
                            value: Value::Null,
                            changed: false
                        };
                        file_table.questions.insert(key, question_part);
                    } else {
                        panic!("Path to value is not a string.");
                    }
                }
            }

            self.tables.push(file_table);
        };

        let mut jsons = Jsons::new();

        if let Err(e) = jsons.open_jsons(&self) {
            panic!("{e}");
        }

        self.sort_modules();
        for module in self.suriconf_struct.modules.clone() {
            self.query_module(&module, &mut jsons);
        }

        self.write_changes(&mut jsons);

        let mut suricata_result_path = PathBuf::from("./tmp");
        if !suricata_result_path.exists() {
            fs::create_dir_all(&suricata_result_path).expect("Unable to create tmp directory.");
        }

        let mut question: Vec<Keys> = Vec::new();
        question.push(Keys::datetime);
        self.check_table_if_null(&question, &mut jsons);
        let answer = self.get_from_table(&question);
        let datetime = answer.iter().find(|h| h.key == &Keys::datetime)
            .and_then(|h| h.value.as_str()).and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .map(|dt| dt.with_timezone(&Utc)).expect("Unable to get datetime.");

        suricata_result_path.push(format!("suricata_result{}.yaml", datetime.format("-%Y-%m-%d-%H:%M:%S")));

        let mut suricata_result = yaml::json_to_yaml(jsons.suricata);
        yaml::fix_interface_cpu_set(&mut suricata_result);

        match yaml::close_yaml(&suricata_result, &suricata_result_path) {
            Err(e) => {panic!("{e}")},
            Ok(()) => {}
        }
    }

    pub fn sort_modules(&mut self) {
        const ORDER: [&Modules; 4] = [&Modules::FlowThreads , &Modules::CpuAffinity, &Modules::Flow, &Modules::MemoryModule];
        self.suriconf_struct.modules.sort_by_key(|m| {
            ORDER.iter()
                .position(|&o| o == m)
                .expect("Unknown module.")
        });
    }

    pub fn query_module(&mut self, module: &Modules, jsons: &mut Jsons) {
        let mut module = create_module(module, &self.suriconf_struct.analysis, self.debug);
        let questions: Vec<Keys> = module.init_questions();
        self.check_table_if_null(&questions, jsons);
        let answers = self.get_from_table(&questions);
        let changes = module.main(&answers);
        if !changes.is_empty() {
            self.change_in_table(changes);
        }
    }
    pub fn check_table_if_null(&mut self, questions: &Vec<Keys>, jsons: &mut Jsons) { // just for first run
        let mut contains  = false;
        for question in questions {
            for table in  &mut self.tables {
                if table.questions.contains_key(question) {
                 contains = !contains;
                 let question_part = table.questions.get_mut(question).expect("Unable to find value.");
                 if let Value::Null = question_part.value {
                     let file_path = if question_part.file_path.as_str().contains("var_index") {
                         let index = self.json_var.var_index.get(question).expect("Unable to find var_index.").as_str().expect("Unable to transform var_index into str.");
                         question_part.file_path = question_part.file_path.replace("var_index", index);
                         question_part.file_path.as_str()
                     }else {
                         question_part.file_path.as_str()
                     };
                     question_part.value  = jsons.get_answer(&table.file_name, file_path);
                 }
                 break;
                }
            }
            
            if !contains {
                panic!("Unable to find required key.")
            }
            contains=!contains;
        }
    }

    pub fn get_from_table<'a>(&'a self, questions: &'a Vec<Keys>) -> Vec<Answer<'a>> {
        let mut answers: Vec<Answer> = Vec::new();
        for question in questions {
            for table in  &self.tables {
                if table.questions.contains_key(question) {
                    let question_part = table.questions.get(question).expect("Unable to find value.");
                        let answer = Answer {key: question, value: &question_part.value};
                    answers.push(answer);
                        break;
                    }
                }
            }
        answers
    }

    pub fn change_in_table(&mut self, changes: Vec<Change>) {
        for change in changes {
            for table in &mut self.tables {
                if table.questions.contains_key(&change.keys) {
                    let question_part = table.questions.get_mut(&change.keys).expect("Unable to find value.");
                    question_part.value = change.value.clone();
                    if table.file_name == FileNames::suricata {
                        question_part.changed = true;
                    }
                }
            }
        }
    }

    pub fn write_changes(&self, jsons: &mut Jsons) {
        let mut change_management_count = 0;
        let mut wrk_cpu_set: Vec<u64> = Vec::new();
        let suricata_table = self.tables.iter().find(|a| a.file_name == FileNames::suricata).expect("Unable to find Suricata table.");
        for question in &suricata_table.questions {
            if matches!(question.0, Keys::flow_managers | Keys::flow_recyclers) {
                change_management_count += question.1.value.as_u64().expect("Unable to get recycler or manager count as u64.")
            }
            if *question.0 == Keys::wrk_cpu_set {
                wrk_cpu_set = question.1.value.as_array().expect("Unable to get wrk_cpu_set.")
                    .iter().map(|a| a.as_u64().expect("Expected u64")).collect();
            }

            if question.1.changed {
                let change = find_in_json_with_path_mut(&mut jsons.suricata, question.1.file_path.as_str());
                *change = question.1.value.clone();
            }
        }
        self.change_management_cpu_set(&mut jsons.suricata, change_management_count, wrk_cpu_set);
        self.disable_preconfiguration_logging(&mut jsons.suricata);
    }

    pub fn change_management_cpu_set(&self, file_value: &mut Value, change_management_count: u64, wrk_cpu_set: Vec<u64>) {
        let management_set = file_value.get_mut("threading").expect("Unable to get threading section.")
            .get_mut("cpu-affinity").and_then(|m| m.get_mut("management-cpu-set")).expect("Unable to parse management-cpu-set.")
            .get_mut("cpu").expect("Unable to get cpus for management-cpu-set.");

        let mut new_managemet_set: Vec<u64> = Vec::new();

        let max_cpu_usage_vec = self.suriconf_struct.max_cpu_usage_vec.clone();
        if self.suriconf_struct.modules.contains(&Modules::CpuAffinity) && self.suriconf_struct.modules.contains(&Modules::FlowThreads) {
            let mut cpu_counter = 0;
            for cpu in &max_cpu_usage_vec {
                if !wrk_cpu_set.contains(cpu) {
                    new_managemet_set.push(*cpu);
                    cpu_counter += 1;
                }
                if cpu_counter == change_management_count {
                    break
                }
            }

            if cpu_counter != change_management_count {
                panic!("Unable to configure Suricata, not enough cpu cores for management.")
            }
            *management_set = new_managemet_set.iter().map(|a| Value::Number(Number::from(*a))).collect()
        }

        else if self.suriconf_struct.modules.contains(&Modules::FlowThreads) {
            if change_management_count > max_cpu_usage_vec.iter().len() as u64 {
                panic!("Unable to configure Suricata, not enough cpu cores for management.")
            }
            new_managemet_set = max_cpu_usage_vec[..change_management_count as usize].to_vec();
            *management_set = new_managemet_set.iter().map(|a| Value::Number(Number::from(*a))).collect()

        }
    }

    pub fn disable_preconfiguration_logging(&self, file_value: &mut Value) {
        if let Some(outputs) = file_value.get_mut("outputs").and_then(|v| v.as_array_mut()) {
            for output in outputs.iter_mut() {
                if let Some(obj) = output.as_object_mut() {
                    if let Some(eve_log) = obj.get_mut("eve-log") {
                        if let Some(eve_obj) = eve_log.as_object_mut() {
                            if let Some(filename) = eve_obj.get("filename").and_then(|f| f.as_str()) {
                                if filename == "flows.json" || filename == "stats.json" {
                                    eve_obj.insert("enabled".to_string(), Value::String("no".to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}