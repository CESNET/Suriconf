/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file contains implementation tests for yaml rust module.
*/
use ::suriconf::yaml;
use serde_yaml_ng::Value;
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    const SURICATA_YAML: &str = "./tests/suricata.yaml";

    fn enabled_of<'a>(outputs: &'a [Value], name: &str) -> Option<&'a Value> {
        outputs
            .iter()
            .find_map(|o| o.get(name))
            .and_then(|v| v.get("enabled"))
    }

    #[test]
    fn yaml_open() {
        let yaml = PathBuf::from(SURICATA_YAML);
        let result = yaml::open_yaml(&yaml);
        assert!(result.is_ok(), "File cannot be opened.");
    }

    #[test]
    fn yaml_open_missing_file() {
        let yaml = PathBuf::from("./tests/does_not_exist.yaml");
        assert!(
            yaml::open_yaml(&yaml).is_err(),
            "Missing file must return an error."
        );
    }

    #[test]
    fn yaml_disable_logging() -> Result<(), Box<dyn std::error::Error>> {
        let mut suricata = yaml::open_yaml(&PathBuf::from(SURICATA_YAML))?;
        yaml::disable_logging(&mut suricata)?;

        let outputs = suricata
            .get("logging")
            .and_then(|l| l.get("outputs"))
            .and_then(|o| o.as_sequence())
            .ok_or("Missing logging outputs.")?;

        let no = Value::String("no".into());
        assert_eq!(enabled_of(outputs, "file"), Some(&no));
        assert_eq!(enabled_of(outputs, "syslog"), Some(&no));
        assert_ne!(enabled_of(outputs, "console"), Some(&no));
        Ok(())
    }

    #[test]
    fn yaml_disable_logging_missing_outputs() -> Result<(), serde_yaml_ng::Error> {
        let mut suricata: Value = serde_yaml_ng::from_str("logging: {}")?;
        assert!(
            yaml::disable_logging(&mut suricata).is_err(),
            "The function disable_logging should fail on a Suricata config without a proper logging section."
        );
        Ok(())
    }
}
