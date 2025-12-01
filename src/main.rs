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
    yaml::close_yaml(&suricata_string, &logs.suri_configuration).unwrap();

    if let Some(result) = suricata::execute_suricata(&suriconf, &mut vec_of_sur_cmd, &mut logs) {
        if !result {
            return;
        }
    } else {
        panic!("Unable to execute Suricata.");
    }

    // PRECONFIGURATION
    let mut preconfiguration = Preconfiguration::new();
    match preconfiguration.create_preconfiguration_structure_and_save(&logs) {
        Err(e) => {
            panic!("{}", e);
        },
        Ok(()) => {}
    }

    // QUERY

}

