/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file contains functional tests for the CLI argument interface.
*/
use ::suriconf::argument::{Args, Commands};
use ::suriconf::structures::{Analysis, CaptureMode, Mode, Modules};
use clap::Parser;
use std::path::PathBuf;

// TODO, add error comments

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_default_values() {
        let args = Args::parse_from(["suriconf"]);

        assert_eq!(args.suricata_config, None);
        assert_eq!(args.suriconf_config, PathBuf::from("suriconf.yaml"));
        assert!(args.mode.is_none());
        assert!(args.modules.is_none());
        assert!(args.cmd.is_none());
        assert!(!args.verbose);
        assert!(args.options.is_empty());
    }

    #[test]
    fn argument_global_options() {
        let args = Args::parse_from([
            "suriconf",
            "-s",
            "/etc/suricata/suricata.yaml",
            "-c",
            "test.yaml",
            "-M",
            "flow",
            "cpu-affinity",
            "flow-threads",
            "memory-usage",
            "-v",
            "-o-k none -vvvv -S /rules/suricata.rules",
        ]);

        assert_eq!(
            args.suricata_config,
            Some(PathBuf::from("/etc/suricata/suricata.yaml"))
        );
        assert_eq!(args.suriconf_config, PathBuf::from("test.yaml"));
        assert_eq!(
            args.modules,
            Some(vec![
                Modules::Flow,
                Modules::CpuAffinity,
                Modules::FlowThreads,
                Modules::MemoryUsage
            ])
        );
        assert!(args.verbose);
        assert_eq!(
            args.options,
            vec!["-k", "none", "-vvvv", "-S", "/rules/suricata.rules"]
        );
    }

    #[test]
    fn argument_suricata_subcommand() {
        let args = Args::parse_from([
            "suriconf",
            "suricata",
            "-b",
            "/usr/bin/suricata",
            "-l",
            "/var/log/suricata",
            "-t",
            "3000",
        ]);

        match args.cmd {
            Some(Commands::Suricata {
                path_to_bin,
                path_to_logs,
                preconf_time,
                analysis,
                ..
            }) => {
                assert_eq!(path_to_bin, Some(PathBuf::from("/usr/bin/suricata")));
                assert_eq!(path_to_logs, Some(PathBuf::from("/var/log/suricata")));
                assert_eq!(preconf_time, Some(3000));
            }
            other => panic!("Expected suricata subcommand, got {other:?}."),
        }
    }

    #[test]
    fn argument_var_subcommand() {
        let args = Args::parse_from([
            "suriconf",
            "var",
            "-i",
            "eth0",
            "-c",
            "af-packet",
            "-m",
            "4096",
            "-C",
            "0-3",
            "4-7",
        ]);

        match args.cmd {
            Some(Commands::Var {
                interface,
                capture_mode,
                max_memory_usage,
                max_cpu_usage_vec,
            }) => {
                assert_eq!(interface, Some("eth0".to_string()));
                assert!(matches!(capture_mode, Some(CaptureMode::AF_PACKET)));
                assert_eq!(max_memory_usage, Some(4096));
                assert_eq!(
                    max_cpu_usage_vec,
                    Some(vec!["0-3".to_string(), "4-7".to_string()])
                );
            }
            other => panic!("Expected var subcommand, got {other:?}."),
        }
    }

    #[test]
    fn argument_init_subcommand() {
        let args = Args::parse_from(["suriconf", "init", "-o", "out.yaml", "-f"]);

        match args.cmd {
            Some(Commands::Init { output, force }) => {
                assert_eq!(output, PathBuf::from("out.yaml"));
                assert!(force);
            }
            other => panic!("Expected init subcommand, got {other:?}."),
        }
    }

    #[test]
    fn argument_invalid_module_is_rejected() {
        let result = Args::try_parse_from(["suriconf", "-M", "unknown-module"]);

        assert!(result.is_err());
    }

    #[test]
    fn argument_invalid_preconf_time_is_rejected() {
        let result = Args::try_parse_from(["suriconf", "suricata", "-t", "soon"]);

        assert!(result.is_err());
    }
}
