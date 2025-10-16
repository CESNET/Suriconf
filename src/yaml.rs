use std::fs::File;
use serde_yaml::Value;
use crate::argument::Args;
use crate::structures::{Suriconf, Mode};
use crate::structures::Commands;

pub fn open_yaml(file: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let text: Value = serde_yaml::from_reader(file)?;
    Ok(text)
}

pub fn create_suriconf_structure(args: &Args, suriconf_string: &Value) -> Suriconf {

    let suri_configuration: String = match &args.suricata_config {
        Some(cfg) => cfg.clone(),
        None => {
            find_suri_configuration(suriconf_string)
                .expect("Unable to find suri-configuration.")
        }
    };

    let mode: Mode = match &args.mode {
        Some(mode) => mode.clone(),
        None => { find_mode(suriconf_string).expect("Unable to decide Suriconf mode.")
        }
        };

    let modules: Vec<String> = match &args.modules {
        Some(modules) => modules.clone(),
        None => {
            find_modules(suriconf_string).expect("Unable to parse modules.")
        }
    };

    let interface = if let Some(Commands::Var { interface: Some(interface), .. }) = &args.cmd {
        interface.clone()
    }
    else {
        find_interface(suriconf_string).expect("Unable to parse interface.")
    };

    let capture_mode = if let Some(Commands::Var {capture_mode: Some(capture_mode), ..}) = &args.cmd {
        capture_mode.clone()
    }
    else {
        find_capture_mode(suriconf_string).expect("Unable to parse capture mode")
    };

    let max_memory_usage = if let  Some(Commands::Var {max_memory_usage: Some(max_memory_usage), ..}) = &args.cmd {
        *max_memory_usage
    }
    else {
        find_max_memory_usage(suriconf_string).expect("Unable to parse max memory usage.")
    };

    let max_cpu_usage = if let Some(Commands::Var {max_cpu_usage: Some(max_cpu_usage), ..}) = &args.cmd {
            *max_cpu_usage
    }
    else {
        find_max_cpu_usage(suriconf_string).expect("Unable to parse max cpu usage.")
    };

    Suriconf {
        suri_configuration,
        mode,
        modules,
        interface,
        capture_mode,
        max_memory_usage,
        max_cpu_usage
    }
}

pub fn find_suri_configuration(text: &Value) -> Option<String> {
    text.get("suri-configuration")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

pub fn find_mode(text: &Value) -> Option<Mode> {
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
    }

    else if modify {
        let modify = text.get("mode")
            .and_then(|m| m.get("modify"))
            .and_then(|m| m.get("yaml_change"))
            ?.as_str()?;
        let mode = match modify {
            "ask" => { Some(Mode::AskModify) },
            "force" => {Some(Mode::ForceModify) },
            _ => None
        };
        mode
    }

    else  {
        Some(Mode::Suggestion)
    }
}

pub fn find_modules(text: &Value) -> Option<Vec<String>> {
    let mut vec_modules: Vec<String> = Vec::new();

    match text.get("modules").and_then(|v| v.as_sequence()) {
        Some(modules) => {
            for module in modules {
                let enabled = module
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if enabled {
                    vec_modules.push(module.get("name")
                                      .and_then(|v| v.as_str())?
                                      .to_string());
                }
            }
            Some(vec_modules)
        }
        None => None
    }
}

pub fn find_interface(text: &Value) -> Option<String> {
    text.get("variables")
        .and_then(|c| c.get("interface"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

pub fn find_capture_mode(text: &Value) -> Option<String> {
    text.get("variables")
        .and_then(|c| c.get("capture_mode"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

pub fn find_max_memory_usage(text: &Value) -> Option<f64> {
    let mut max_memory_usage_iter = text.get("variables")
        .and_then(|c| c.get("max_memory_usage"))
        .and_then(|c| c.as_str())?.split(" ");

    let number: f64 = max_memory_usage_iter.next()?.parse::<f64>().ok()?;
    let unit =  max_memory_usage_iter.next()?;
    match unit  {
        "GiB" => {Some(1_024f64 * 1_024f64 * 1_024f64 * number)},
        "MiB" => {Some(1_024f64 * 1_024f64 * number)},
        "KiB" => {Some(1_024f64 * number)},
        "B" => {Some(number)},
        _ => None
    }
}

pub fn find_max_cpu_usage(text: &Value)  -> Option<u64>{
    text.get("variables")
        .and_then(|c| c.get("max_cpu_usage"))
        .and_then(|c| c.as_u64())
}