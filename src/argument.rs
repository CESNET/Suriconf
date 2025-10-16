use clap::{Parser};
use crate::structures::Commands;
use crate::structures::Mode;

/// Suriconf - Configuration Assistant for Suricata
#[derive(Parser, Debug)]
#[clap(version)]
pub struct Args {

    /// Specify Suriconf configuration file
    #[clap(short='c', long="conf", default_value="suriconf.yaml")]
    pub suriconf_config: String,

    /// Specify Suricata configuration file
    #[clap(short='s', long="sconf")]
    pub suricata_config: Option<String>,

    /// Specify Suriconf configuration mode 
    #[clap(short='m', long="mode", value_enum)]
    pub mode: Option<Mode>,

    /// Select modules with which Suriconf will run
    #[clap(short='M', long, value_delimiter = ' ', num_args = 1..)]
    pub modules: Option<Vec<String>>,

    pub bin: Option<String>,

    #[command(subcommand)]
    pub cmd: Option<Commands>,
}
