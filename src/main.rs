/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file is a startpoint for Suriconf.
*/

use chrono::{DateTime, Utc};
use clap::Parser;
use std::time::SystemTime;
use suriconf::argument::Args;
use suriconf::json::Preconfiguration;
use suriconf::query::Resources;
use suriconf::structures::{CreatedLogs, JsonVar, SuricataAgain};
use suriconf::suricata;
use suriconf::yaml;
use suriconf::yaml::Suriconf;

#[allow(unused_variables)]
fn main() {
    let args = Args::parse();

    let suriconf_string = match yaml::open_yaml(&args.suriconf_config) {
        Ok(suriconf_string) => suriconf_string,
        Err(e) => {
            panic!("{e}");
        }
    };

    let mut suriconf: Suriconf = Suriconf::init_suriconf_structure();
    suriconf.create_suriconf_structure(&args, &suriconf_string);

    let mut suricata_string = match yaml::open_yaml(&suriconf.suri_configuration) {
        Ok(suricata_string) => suricata_string,
        Err(e) => {
            panic!("{e}");
        }
    };

    match yaml::check_enable_stats_log(&mut suricata_string) {
        Err(e) => {
            panic!("{e}");
        }
        Ok(()) => {}
    }
    let mut json_var: JsonVar = Default::default();

    let system_time = SystemTime::now();
    let datetime: DateTime<Utc> = system_time.into();
    match yaml::check_set_cpu_affinity(&mut suricata_string, &suriconf, &mut json_var, &datetime) {
        Err(e) => {
            panic!("{e}")
        }
        Ok(()) => {}
    };

    match suriconf.find_suricata_executable_file() {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    match suriconf.find_ethtool_executable_file() {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    match suriconf.find_ifconfig_executable_file() {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    match suriconf.find_ip_executable_file() {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    match suriconf.check_read_write_for_log_dir() {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    let mut logs = CreatedLogs::new(&suriconf.log_dir, &datetime);
    yaml::close_yaml(&suricata_string, &logs.suri_configuration).unwrap();

    suricata::check_min_suricata_runtime_for_modules(&suriconf);

    let sys = loop {
        let (sys, suricata_again) =
            match suricata::execute_suricata(&suriconf, &mut logs, &args.options) {
                Some((sys, suricata_again)) => {
                    if sys.threads.is_empty() {
                        panic!("Unable to get data from Suricata.");
                    }
                    (sys, suricata_again)
                }
                _ => {
                    return;
                }
            };
        if suricata_again == SuricataAgain::Done {
            break sys;
        }
    };

    // PRECONFIGURATION
    let mut preconfiguration = Preconfiguration::new(sys, datetime);
    match preconfiguration.create_preconfiguration_structure_and_save(&logs) {
        Err(e) => {
            panic!("{}", e);
        }
        Ok(()) => {}
    }

    // QUERY
    let mut resources = Resources::new(
        logs.suri_configuration,
        suriconf,
        args.suriconf_config,
        logs.preconfiguration,
        json_var,
        args.verbose,
    );
    resources.main_query();
}
