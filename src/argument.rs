/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file provides a parameter interface.
*/

use clap::{Parser, Subcommand};
use std::path::{PathBuf};
use crate::structures::{Analysis, Mode, CaptureMode, Modules};

/// Suriconf - Configuration Assistant for Suricata
#[derive(Parser, Debug)]
#[clap(version)]
pub struct Args {

    /// Specify Suricata configuration file
    #[clap(short='s', long="sconf")]
    pub suricata_config: Option<PathBuf>,

    /// Specify Suriconf configuration file
    #[clap(short='c', long="conf", default_value="suriconf.yaml")]
    pub suriconf_config: PathBuf,

    /// Specify Suriconf configuration mode 
    #[clap(short='m', long, value_enum)]
    pub mode: Option<Mode>,

    /// Select modules with which Suriconf will run
    #[clap(short='M', long, value_enum, value_delimiter = ' ', num_args = 1..)]
    pub modules: Option<Vec<Modules>>,

    #[command(subcommand)]
    pub cmd: Option<Commands>,

    /// Activate debug mode in Suriconf
    #[clap(short='v', long)]
    pub verbose: bool,

    /// Suricata cmdline options
    #[clap(short='o', long, value_delimiter = ' ', num_args = 1..)]
    pub options: Vec<String>
}

#[derive(Subcommand, Debug)]
pub enum Commands {

    /// Change defaults for Suricata
    Suricata {
        /// Change path to bin
        #[clap(short='b', long)]
        path_to_bin: Option<PathBuf>,

        /// Ethtool path to bin
        #[clap(short='e', long)]
        ethtool_bin: Option<PathBuf>,

        /// Ifconfig path to bin
        #[clap(short='i', long)]
        ifconfig_bin: Option<PathBuf>,

        /// IP path to bin
        #[clap(short='p', long)]
        ip_bin: Option<PathBuf>,

        /// Change path to logs
        #[clap(short='l', long)]
        path_to_logs: Option<PathBuf>,

        /// Change the time of Suricata preconfiguration run (in seconds)
        #[clap(short='t', long="time")]
        preconf_time: Option<u64>,

        /// Specify Suriconf analysis
        #[clap(short='a', long)]
        analysis: Option<Analysis>
    },

    /// Change variable section in Suriconf configuration file
    Var {
        /// Change interface
        #[clap(short, long)]
        interface: Option<String>,

        /// Change capture mode
        #[clap(short, long, value_enum)]
        capture_mode: Option<CaptureMode>,

        /// Change max memory usage
        #[clap(short='m', long="memory")]
        max_memory_usage: Option<u64>,

        /// Change max cpu usage
        #[clap(short='C', long="cpu", value_delimiter = ' ', num_args = 1..)]
        max_cpu_usage_vec: Option<Vec<u64>>,
    }
}