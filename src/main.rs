

mod argument;
mod yaml;

use clap::{Parser};
use argument::Args;

#[allow(unused_variables)]
fn main() {

    let args = Args::parse();
    yaml::open_yaml(&args.suriconf_config);

    //

}

