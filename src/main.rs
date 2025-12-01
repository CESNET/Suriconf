use clap::{Parser};
use suriconf::argument::Args;
use suriconf::yaml;
use suriconf::yaml::Suriconf;
use suriconf::json::Preconfiguration;
use suriconf::json;
use suriconf::structures::CreatedLogs;
use suriconf::suricata;

#[allow(unused_variables)]
fn main() {

    let args = Args::parse();

    let suriconf_string = match yaml::open_yaml(&args.suriconf_config) {
        Ok(suriconf_string) => {suriconf_string},
        Err(e) => {
            panic!("{}", e);
        }
    };

    let mut suriconf: Suriconf = yaml::Suriconf::init_suriconf_structure();
    suriconf.create_suriconf_structure(&args, &suriconf_string);

    let mut suricata_string = match yaml::open_yaml(&suriconf.suri_configuration) {
        Ok(suricata_string) => {suricata_string},
        Err(e) => {
            panic!("{}", e);
        }
    };

    let mut vec_of_sur_cmd: Vec<&str> = vec![];
    match yaml::check_enable_stats_log(&mut suricata_string, &mut vec_of_sur_cmd) {
        Err(e) => {
            panic!("{}", e);
        },
        Ok(()) => {}
    }

    match suriconf.find_suricata_executable_file() {
        Err(e) => {
            panic!("{}", e);
        },
        Ok(()) => {}
    }

    let mut logs = CreatedLogs::new(&suriconf.log_dir);
    yaml::close_yaml(&suricata_string, &suriconf.suri_configuration, &logs).unwrap();

    if let Some(result) = suricata::execute_suricata(&suriconf, &mut vec_of_sur_cmd, &mut logs) {
        if !result {
            return;
        }
    } else {
        panic!("Unable to execute Suricata.");
    }

    let mut stats =  match json::open_json(&logs.stats) {
        Ok(stats) => {stats},
        Err(e) => {
            panic!("{}",e);
        }
    };

    let mut preconfiguration = Preconfiguration::new();
    preconfiguration.create_preconfiguration_structure(&stats);
}

