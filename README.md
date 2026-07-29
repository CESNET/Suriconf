# Suriconf: configuration assistant for Suricata

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://rustup.rs/)
[![Bachelor's Thesis](https://img.shields.io/badge/thesis-completed-success)](https://www.vut.cz/studenti/zav-prace/detail/170986)

Suriconf is an automated configuration assistant for [Suricata](https://github.com/OISF/suricata). It analyzes network traffic and system resources to optimize Suricata's configuration through a modular approach. Each module uses mathematical methods and performance metrics to configure specific Suricata components. Testing showed Suriconf v1.0-dev successfully configured Suricata in 80.8% of test cases with [rules](https://community.emergingthreats.net/).

## Contents

---
  - [Prerequisites](#prerequisites)
    - [Rust toolchain](#rust-toolchain)
  - [Configuration](#configuration)
    - [Configuration overview](#configuration-overview)
    - [Modules](#modules)
    - [Variables](#variables)
  - [Usage](#usage)
  - [Output](#output)
---

## Prerequisites

### Rust toolchain
1. Install Rustup from [rustup.rs](https://rustup.rs/).
2. Verify your Rust version: `rustc --version`.

> [!WARNING]
> Minimum required version of rustc is 1.88 or higher.

### Required binaries

The following tools must be installed, and their paths must be accessible and specified in the configuration file.

| Tool | Version |
|------|---------|
| Suricata | 9.0.0-dev (d030a9c4e 2026-04-01) |
| ethtool | 5.13 |
| ifconfig | net-tools 2.10-alpha |
| ip | iproute2-6.8.0, libbpf 0.5.0 |

## Configuration

### Configuration overview

The entire configuration is defined in a YAML file, typically named `suriconf.yaml`.

| Parameter | Description                                                                                                                                                                                                                                      |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `suri-configuration` | Path to the default Suricata configuration file.                                                                                                                                                                                      |
| `log-dir` | Directory for Suricata logs (requires read/write permissions).                                                                                                                                                                                   |
| `preconf-time` | Duration of the Suricata preconfiguration run.                                                                                                                                                                                              |
| `analysis` | Analysis type: `dynamic` (multiple Suricata runs) or `static` (single Suricata run).                                                                                                                                                            |
| `mode` | Output mode: `suggestion` (recommendations only) or `modify` (writes changes to Suricata configuration file).<br>Modify mode with `yaml_change`: `ask` (user confirms each change) or `force` (all detected changes arre applied automatically).    | 

> [!WARNING]
> - Flow threads module requires minimum 6 minutes (`preconf-time`).
> - Version 1.0-dev supports only `static` analysis.
> - Version 1.0-dev supports only `modify` mode with `yaml_change: force`.


### Modules

The `modules` section defines all available modules. Each module can be enabled or disabled using the `enabled` parameter (`true` / `false`).

> [!NOTE]
> For disabled modules, Suriconf uses the default configuration from the Suricata configuration file.

> [!WARNING]
> When disabling `cpu_affinity` module, you must define interface-specific CPU affinity section in default Suricata configuration file.

### Variables

The `variables` section defines runtime and hardware settings.

| Setting              | Description                                            |
|----------------------|--------------------------------------------------------|
| `interface`          | Network interface used by Suricata.                    |
| `capture_mode`       | Only AF_PACKET (`af_packet`) supported.                |
| `max_memory_usage`   | Maximum memory usage limit for Suricata configuration. |
| `max_cpu_usage_vec`  | Logical cores for Suricata configuration.              |

**CPU allocation**
- **Management threads** (when `flow_threads` module enabled): taken from `max_cpu_usage_vec` vector.
- **Worker threads** (when `cpu_affinity` module enabled): assigned from remaining cores, limited by RX RSS queue count (fewer queues = fewer cores used).

## Usage

Isolate CPU cores specified in the `max_cpu_usage_vec` vector to prevent interference from other processes.

Isolate cores 2-4 using `grubby`:

```bash
sudo grubby --update-kernel=ALL --args="isolcpus=2-4" && sudo reboot
```

Use the Cargo package manager to run the project in `src` directory:

```bash
cargo run
```

To display available options, pass the `-h` flag after `--`:

```bash
cargo run -- -h
```

> [!NOTE]
> All Suriconf parameters must be passed after `--`.

## 4. Output
The expected output should be a successful configuration process that creates `suricata_result.yaml` and `nic_setup.sh`, both with the same timestamp.

> [!IMPORTANT]
> Execute `nic_setup.sh` before running Suricata to apply network interface settings.
