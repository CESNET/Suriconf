

use clap::{Parser};
use suriconf::argument::Args;
use suriconf::yaml;
use suriconf::structures::Suriconf;

#[allow(unused_variables)]
fn main() {

    let args = Args::parse();

    let suriconf_string = match yaml::open_yaml(&args.suriconf_config) {
        Ok(suriconf_string) => {suriconf_string},
        Err(e) => {
            panic!("Error: {}", e);
        }
    };

    let mut suriconf: Suriconf = yaml::create_suriconf_structure(&args, &suriconf_string);
    println!("{:#?}", suriconf);

    // yaml should have enabled stats.log


    // git precommit hooks

}

