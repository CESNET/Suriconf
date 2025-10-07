use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    AskModify,
    ForceModify,
    Suggestion
}

/// Suriconf - Configuration Assistant for Suricata
#[derive(Parser, Debug)]
#[clap(version)]
pub struct Args {

    /// Specify Suriconf configuration file
    #[clap(short='c', long="conf", default_value="suriconf.yaml")]
    pub suriconf_config: String,

    /// Specify Suricata configuration file
    #[clap(short='s', long="sconf")]
    suricata_config: Option<String>,

    /// Specify Suriconf configuration mode 
    #[clap(short='m', long="mode", value_enum, default_value_t=Mode::Suggestion)]
    mode: Mode,

    /// Select modules with which Suriconf will run
    #[clap(short='M', long, value_delimiter = ' ', num_args = 1..)]
    modules: Option<Vec<String>>,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Change variable section in Suriconf configuration file
    Var {
        /// Change interface
        #[clap(short, long)]
        interface: String,

        /// Change capture mode
        #[clap(short, long, default_value="dpdk")]
        capture_mode: String,

        /// Change max memory usage
        #[clap(short='m', long="memory")]
        max_memory_usage: u32,

        /// Change max cpu usage
        #[clap(short='C', long="cpu")]
        max_cpu_usage: String
    }
}
