# Suriconf: configuration assistant for Suricata

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://rustup.rs/)
[![Bachelor's Thesis](https://img.shields.io/badge/thesis-completed-success)](https://www.vut.cz/studenti/zav-prace/detail/170986)

## Contents
---
- [Bugs](#bugs)
- [Future work](#future-work)
- [Code quality](#code-quality)
- [Tests](#tests)
---

## Bugs
- The YAML file is converted to JSON and then back to YAML for searching, which can alter the original formatting and is therefore not fully correct. A hotfix function was introduced specifically for the purposes of the bachelor’s thesis. 
- Better estimation of TCP overhead.
- CPU affinity module should work with `check_nic_warning_counter`, `get_capture_errors_stat` functions.
- Flow module should use sync counters.
- The `tcp_reuse` timeout is not considered.
- The calculations for flow_memcap and stream_memcap do not account for all memory components in some cases.
- Fragment structures are not included in `defrag_memuse` at all. (Suricata)
- Hotfix for defrag_memcap, needs further analysis.
- Check for parameter changes (CLI) in Suriconf. (CPU affinity module)
- Do not check cpu set if the cpu affinity module is off. 
- Create missing sections of the Suricata YAML. 

## Future work
- Add load factor for hash tables in memory module.
- Reallocate memory when a memcap limit is reached - LP.
- Offline Suriconf should not execute Suricata - skip preconfiguration run. Take metrics and statistic from existing files. 
- Do not log counters with zero values. Adapt the program to handle missing counters. (stats.json)
- Module for rules optimalization. 
- Flow manager and recycler should be configurable on one logical core.
- Make the stats logging interval configurable (currently fixed at 5 seconds).
- Support DPDK capture mode. 

## Code quality
- Remove panics from source code.

## Tests
- Test Theil-Sen regression.
- How do the Suricata parameters `default-packet-size` and `max-pending-packets` affect performance?
- Write functional testing.
