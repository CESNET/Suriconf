use clap::{Subcommand, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    AskModify,
    ForceModify,
    Suggestion
}

#[derive(Debug)]
pub struct Suriconf {
    pub suri_configuration: String,
    pub mode: Mode,
    pub modules: Vec<String>,
    pub interface: String,
    pub capture_mode: String,
    pub max_memory_usage: f64,
    pub max_cpu_usage: u64
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Change variable section in Suriconf configuration file
    Var {
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