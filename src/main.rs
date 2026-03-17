use clap::{arg, Parser};
use suriconf::argument::Args;
use suriconf::yaml;
use suriconf::yaml::Suriconf;
use suriconf::json::Preconfiguration;
use suriconf::structures::{CreatedLogs, JsonVar};
use suriconf::suricata;
use suriconf::query::Resources;

#[allow(unused_variables)]
fn main() {

    let args = Args::parse();

    let suriconf_string = match yaml::open_yaml(&args.suriconf_config) {
        Ok(suriconf_string) => {suriconf_string},
        Err(e) => {
            panic!("{e}");
        }
    };

    let mut suriconf: Suriconf = yaml::Suriconf::init_suriconf_structure();
    suriconf.create_suriconf_structure(&args, &suriconf_string);

    let mut suricata_string = match yaml::open_yaml(&suriconf.suri_configuration) {
        Ok(suricata_string) => {suricata_string},
        Err(e) => {
            panic!("{e}");
        }
    };

    match yaml::check_enable_stats_log(&mut suricata_string) {
        Err(e) => {
            panic!("{e}");
        },
        Ok(()) => {}
    }

    let mut json_var: JsonVar = Default::default();
    match yaml::check_set_cpu_affinity(&mut suricata_string, &suriconf, &mut json_var) {
        Err(e) => {
            panic!("{e}")
        },
        Ok(()) => {}
    };

    match suriconf.find_suricata_executable_file() {
        Err(e) => {
            panic!("{}", e);
        },
        Ok(()) => {}
    }

    let mut logs = CreatedLogs::new(&suriconf.log_dir);
    yaml::close_yaml(&suricata_string, &logs.suri_configuration).unwrap();

    let sys = if let Some(sys) = suricata::execute_suricata(&suriconf, &mut logs) {
        if sys.threads.is_empty() {
            panic!("Unable to get data from Suricata.");
        }
        sys
    } else {
        return;
    };

    // PRECONFIGURATION
    let mut preconfiguration = Preconfiguration::new(sys.threads);
    match preconfiguration.create_preconfiguration_structure_and_save(&logs) {
        Err(e) => {
            panic!("{}", e);
        },
        Ok(()) => {}
    }

    // QUERY
    let mut resources =  Resources::new(logs.suri_configuration, suriconf, args.suriconf_config, logs.preconfiguration, json_var, args.verbose);
    resources.main_query();
}

