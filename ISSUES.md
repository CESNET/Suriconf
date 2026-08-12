# Suriconf: configuration assistant for Suricata

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://rustup.rs/)
[![Bachelor's Thesis](https://img.shields.io/badge/thesis-completed-success)](https://www.vut.cz/studenti/zav-prace/detail/170986)

## Contents

---
- [Bugs](#bugs)
- [Code Quality](#code-quality)
- [Features](#features)
- [Future Work](#future-work)
- [Improvements](#improvements)
- [Tests](#tests)
---

## Bugs
- The YAML file is converted to JSON and then back to YAML for searching, which can alter the original formatting and is therefore not fully correct. A hotfix function was introduced specifically for the purposes of the bachelor’s thesis.
- The regression sometimes has fewer samples than requires. 
- Disable syslog and suricata.log logging after configuration.
- Better estimation of TCP overhead.
- CPU affinity module should work with `check_nic_warning_counter`, `get_capture_errors_stat` functions.
- Flow module should use sync counters.
- The `tcp_reuse` timeout is not considered.
- The calculations for flow_memcap and stream_memcap do not account for all memory components in some cases.
- Fragment structures are not included in `defrag_memuse` at all. (Suricata)
- Do not log counters with zero values. Adapt the program to handle missing counters.

## Code quality
- The recycler and manager use the same mechanism, resulting in duplicated code.
- Use shell-check for bash scripts, improve test automation.
- Refactor logging using Rust crates.

## Future work
- Add load factor for hash tables in memory module. 

## Features
- Specify logical cores as a range in suricata.yaml.

## Tests
- Test Theil-Sen regression.
- How do the Suricata parameters `default-packet-size` and `max-pending-packets` affect performance?
- Write functional testing.
