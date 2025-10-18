use clap::{Parser};
use suriconf::argument::Args;
use suriconf::yaml;
use suriconf::yaml::Suriconf;
use suriconf::suricata::Preconfiguration;

#[allow(unused_variables)]
fn main() {

    let args = Args::parse();

    let suriconf_string = match yaml::open_yaml_to_read(&args.suriconf_config) {
        Ok(suriconf_string) => {suriconf_string},
        Err(e) => {
            panic!("{}", e);
        }
    };

    let mut suriconf: Suriconf = yaml::Suriconf::init_suriconf_structure();
    suriconf.create_suriconf_structure(&args, &suriconf_string);

    let suricata_string = match yaml::open_yaml_to_read(&suriconf.suri_configuration) {
        Ok(suricata_string) => {suricata_string},
        Err(e) => {
            panic!("{}", e);
        }
    };

    let mut vec_of_sur_cmd: Vec<&str> = vec![];
    match yaml::check_enable_stats_log(&suricata_string, &mut vec_of_sur_cmd) {
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

    let mut preconfiguration = Preconfiguration::new();
    preconfiguration.execute_suricata(&suriconf, &mut vec_of_sur_cmd);
}

