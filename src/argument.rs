use clap::{Parser, Subcommand, ValueEnum};
use std::path::{PathBuf};

/// Suriconf - Configuration Assistant for Suricata
#[derive(Parser, Debug)]
#[clap(version)]
pub struct Args {

    /// Specify Suriconf configuration file
    #[clap(short='c', long="conf", default_value="suriconf.yaml")]
    pub suriconf_config: PathBuf,

    /// Specify Suricata configuration file
    #[clap(short='s', long="sconf")]
    pub suricata_config: Option<PathBuf>,

    /// Specify Suriconf configuration mode 
    #[clap(short='m', long="mode", value_enum)]
    pub mode: Option<Mode>,

    /// Select modules with which Suriconf will run
    #[clap(short='M', long, value_delimiter = ' ', num_args = 1..)]
    pub modules: Option<Vec<String>>,

    #[command(subcommand)]
    pub cmd: Option<Commands>,
}

#[derive(Parser, Debug)]
pub struct CommonArgs {

    /// Change path to bin
    #[clap(short='b', long)]
    pub path_to_bin: Option<PathBuf>,

    /// Change path to logs
    #[clap(short='l', long)]
    pub path_to_logs: Option<PathBuf>,

    /// Change the time of Suricata preconfiguration run (in seconds)
    #[clap(short='t', long="time")]
    pub preconf_time: Option<u64>, // TODO check
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    AskModify,
    ForceModify,
    Suggestion
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Change defaults for Suricata
    Suri {
        #[command(flatten)]
        common: CommonArgs
    },

    /// Change variable section in Suriconf configuration file
    Var {
        #[command(flatten)]
        common: CommonArgs,

        /// Change interface
        #[clap(short, long)]
        interface: Option<String>,

        /// Change capture mode
        #[clap(short, long)]
        capture_mode: Option<String>,

        /// Change max memory usage
        #[clap(short='m', long="memory")]
        max_memory_usage: Option<f64>,

        /// Change max cpu usage
        #[clap(short='C', long="cpu")]
        max_cpu_usage: Option<u64>,
    }
}
// TODO check arguments