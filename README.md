# Suricata-autoconfigurer

An information manual for setting up Suriconf, a configuration assistant for Suricata.

---

- [Suricata-autoconfigurer](#suricata-autoconfigurer)
  - [1. Dependencies](#1-dependencies)
  - [2. Suriconf Configuration](#2-suriconf-configuration)
    - [2.1 Configuration Overview](#21-configuration-overview)
    - [2.2 Modules](#22-modules)
    - [2.3 Variables](#23-variables)
  - [3. How to Run](#3-how-to-run)
  - [4. Expected Output](#4-expected-output)

---

## 1. Dependencies

It is necessary to install **rustup**. Installation instructions are available at:  
https://rustup.rs/
> [!WARNING]
The Rust compiler version must be higher than 1.88.

The remaining dependencies required by Suriconf are defined in its configuration. These binaries must be installed and their paths provided in the configuration file. The required tools include:

- Suricata (version 9.0.0-dev (d030a9c4e 2026-04-01))
- ethtool (version 5.13)
- ifconfig (net-tools 2.10-alpha)
- ip (ip utility, iproute2-6.8.0, libbpf 0.5.0)

---

## 2. Suriconf configuration file

### 2. 1. Configuration Overview

- The entire configuration is defined in a YAML file, typically named `suriconf.yaml`.

- The default Suricata configuration file is specified by the **`suri-configuration`** parameter.

- The **`log-dir`** parameter defines the directory where Suricata logs are stored.  
  This directory must have read and write permissions.

- The **`preconf-time`** parameter defines the duration of the Suricata preconfiguration run.  
  > [!WARNING] 
  The flow threads module requires a minimum of 6 minutes to configure properly.

- The **`analysis`** parameter determines whether Suricata performs multiple runs with different configuration options (dynamic) or whether all decisions are derived from a single preconfiguration run (static).  
  > [!WARNING]
  In version 1.0-dev, only static analysis is supported.

- The **mode** defines whether Suriconf writes changes directly into the configuration file or only provides configuration suggestions:
    - suggestion mode: only recommendations are provided
    - modify mode: configuration is modified automatically

- The **modify mode** includes two submodes:
    - ask mode (user confirms changes)
    - force mode (all detected changes are applied automatically)

    > [!WARNING]
    In version 1.0-dev, only **modify mode with `yaml_change: force`** is supported.

---

### 2. 2. Modules

- The `modules` section defines all available modules.
- Each module can be enabled or disabled using the `enabled` parameter (`true` / `false`).
- If a module is disabled, Suricata uses its default configuration from `suricata.yaml`.

> [!WARNING]
When disabling the `cpu_affinity` module, an interface-specific CPU affinity configuration must be defined in `suricata.yaml`.

---

### 2. 3. Variables

- The `variables` section defines runtime and hardware-related settings:
    - network interface used by Suricata
    - packet capture mode (only AF_PACKET)
    - maximum memory usage
    - CPU core vector used by Suriconf

- The CPU vector defines logical cores intended for Suriconf configuration and later selection for Suricata execution.

- If `flow_threads` is enabled:
    - management threads are taken from the `max_cpu_usage` vector

- When `cpu_affinity` is enabled at startup:
    - remaining cores from the `max_cpu_usage` vector are assigned to worker threads
    - the number of allocated CPU cores corresponds to the number of RX RSS queues of the network interface

---

## 3. How to run

One of the highly recommended practices, or even a requirement when running Suriconf, is isolating CPU cores specified in the `max_cpu_usage` vector.
The purpose of this is to prevent Suriconf from producing inaccurate estimates due to interference from other processes consuming CPU resources.
One possible approach is to use the `grubby` kernel parameter. Below is an example of isolating CPU cores 2 to 4, followed by a system reboot:

```bash
sudo grubby --update-kernel=ALL --args="isolcpus=2-4" && sudo reboot
```

Use the Cargo package manager to run the project in `src` directory:

```bash
cargo run
```

To display available options, pass the -h flag after -- (all Suriconf parameters has to be behind --):

```bash
cargo run -- -h
```

---

## 4. Expected output 
The expected output should be a successful configuration process that creates `suricata_result.yaml` and `nic_setup.sh` (used for configuring the NIC and **must be executed before running Suricata**), both with the same timestamp.

---


## 5. Bachelor's thesis testing
All testing results are saved in directory `bt_tests_results` and resources used during testing are in directory `bt_tests_resources`. The Suriconf binary is stored in `src`.
