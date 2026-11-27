/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file is a startpoint for Suriconf.
*/

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use clap::Parser;
use std::time::SystemTime;
use suriconf::argument::{Args, Commands};
use suriconf::config_gen::init;
use suriconf::json::Preconfiguration;
use suriconf::query::Resources;
use suriconf::structures::{CreatedLogs, JsonVar, SuricataAgain};
use suriconf::yaml::Suriconf;
use suriconf::{suricata, suricata_tun, yaml};

#[allow(unused_variables)]
fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    if let Some(Commands::Init { output, force }) = &args.cmd {
        init(output, *force)
            .with_context(|| format!("Failed to generate {}.", output.display()))?;
        return Ok(());
    }

    let suriconf_string = yaml::open_yaml(&args.suriconf_config)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| {
            format!(
                "Failed to open the Suriconf config {}.",
                args.suriconf_config.display()
            )
        })?;

    let mut suriconf: Suriconf = Suriconf::init_suriconf_structure();
    suriconf.create_suriconf_structure(&args, &suriconf_string);

    let mut suricata_string = yaml::open_yaml(&suriconf.suri_configuration)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| {
            format!(
                "Failed to open the Suricata config {}.",
                suriconf.suri_configuration.display()
            )
        })?;

    yaml::check_enable_stats_log(&mut suricata_string)
        .map_err(anyhow::Error::msg)
        .context("Failed to enable stats logging in the Suricata config.")?;

    if args.verbose < 3 {
        yaml::disable_logging(&mut suricata_string)
            .map_err(anyhow::Error::msg)
            .context("Failed to disable Suricata logging.")?;
    }

    let mut json_var: JsonVar = Default::default();

    let system_time = SystemTime::now();
    let datetime: DateTime<Utc> = system_time.into();
    suricata_tun::check_set_cpu_affinity(&mut suricata_string, &suriconf, &mut json_var, &datetime)
        .map_err(anyhow::Error::msg)
        .context("Failed to set CPU affinity in the Suricata config.")?;

    suriconf
        .find_suricata_executable_file()
        .map_err(anyhow::Error::msg)
        .context("Suricata executable not found.")?;

    suriconf
        .find_ethtool_executable_file()
        .map_err(anyhow::Error::msg)
        .context("Ethtool executable not found.")?;

    suriconf
        .find_ip_executable_file()
        .map_err(anyhow::Error::msg)
        .context("Ip executable not found.")?;

    suriconf
        .check_read_write_for_log_dir()
        .map_err(anyhow::Error::msg)
        .context("Log directory is not accessible.")?;

    let mut logs = CreatedLogs::new(&suriconf.log_dir, &datetime);
    yaml::close_yaml(&suricata_string, &logs.suri_configuration)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| {
            format!(
                "Failed to save the Suricata config {}.",
                logs.suri_configuration.display()
            )
        })?;

    suricata::check_min_suricata_runtime_for_modules(&suriconf);

    let sys = loop {
        let (sys, suricata_again) =
            match suricata::execute_suricata(&suriconf, &mut logs, &args.options) {
                Some((sys, suricata_again)) => {
                    if sys.threads.is_empty() {
                        return Err(anyhow!("Unable to get data from Suricata."));
                    }
                    (sys, suricata_again)
                }
                _ => return Ok(()),
            };
        if suricata_again == SuricataAgain::Done {
            break sys;
        }
    };

    // PRECONFIGURATION
    let mut preconfiguration = Preconfiguration::new(sys, datetime);
    preconfiguration
        .create_preconfiguration_structure_and_save(&logs)
        .map_err(|e| anyhow!("{e}"))
        .context("Failed to create the preconfiguration.")?;

    // QUERY
    let mut resources = Resources::new(
        logs.suri_configuration,
        suriconf,
        args.suriconf_config,
        logs.preconfiguration,
        json_var,
        args.verbose > 1,
    );
    resources.main_query();

    Ok(())
}
