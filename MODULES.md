# Suriconf: configuration assistant for Suricata

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://rustup.rs/)
[![Bachelor's Thesis](https://img.shields.io/badge/thesis-completed-success)](https://www.vut.cz/studenti/zav-prace/detail/170986)

## Contents

---
- [Suriconf pipeline](#suriconf-pipeline)
  - [Preconfiguration stage](#preconfiguration-stage)
  - [Query and Execute stage](#query-and-execute-stage)
- [Modules](#modules)
    - [CPU affinity](#cpu-affinity)
    - [Memory usage](#memory-usage)
    - [Flow](#flow)
    - [Flow threads](#flow-threads)
---


## Suriconf pipeline

At the start, the user must provide both the Suricata configuration file (which can be the default one) and the Suriconf configuration file. See instructions in [README.md](README.md).

In static analysis mode, Suriconf operates in two main stages:

```
┌──────────┐
│   User   │
└────┬─────┘
     │ suricata.yaml
     │ suriconf.yaml
     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Preconfiguration stage                                                │
│  - execute Suricata on network interface                               │
│  - collect performance data                                            │
│  - save logs                                                           │
└─────────────────────┬──────────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Query and Execute stage                                               │
│  - request keys for required data                                      │
│  - run modules with required data in dependency order                  │
│  - write all changes to suricata_result.yaml and nic_setup.sh          │
└────────────────────────────────┼───────────────────────────────────────┘
                                 │
                                 ▼
                          suricata_result.yaml (optimized config)
                          nic_setup.sh (network interface setup script)
                          
```

### Preconfiguration stage
The first stage performs a Suricata preconfiguration run on a defined network interface. During this run, the system collects performance data about the system that will be configured, such as CPU core load, and saves logs about the observed network traffic. 

### Query and Execute stage
This stage serves as the primary interface for communication between Suriconf and its modules. During this phase, the system interacts with individual modules to retrieve their calculated configurations and writes them to the resulting Suricata configuration file.

The Query and Execute stage sorts the modules based on configuration dependencies:

1. **Flow threads** – specifies the number of management threads (recycler and manager threads).
2. **CPU affinity** – assignment of CPU cores to worker threads.
3. **Flow** – sets flow memcap, flow hashsize and number of preallocated flow objects.
4. **Memory usage** – specifies memcaps and controls limits of memory (stream, reassembly, ippair, defragmentation, host settings).

This ordering is critical. For example, the number of CPU cores must be determined before initializing the Flow module, since its memcap must provide sufficient memory for preallocated flow objects for each thread.

## Modules

### CPU affinity

The CPU affinity module configures the number of worker threads and defines the logical CPU cores to which they are pinned (a single worker is exclusively assigned to a specific logical core with the highest priority).

**Preconfiguration run**

During the preconfiguration run, Suricata workers use logical cores that are specified in the configuration file vector and are not utilized by other threads (management), with the maximum number limited by the available RX RSS queues. All CPU affinity key features are applied in this stage for better performance estimation, except for NUMA locality determination, since all cores are running and no selection is needed.

**Key features**
- Detects which network interface is associated with each NUMA node and attempts to use CPU cores from the corresponding node to take advantage of NUMA locality.
- Uses the `ethtool` tool to configure RSS (Receive Side Scaling) and AF_PACKET affinity.
- Assigns the appropriate IRQs to each core (each core is assigned to a single RSS queue).
- Disables hardware offloading features.
- If there are fewer RSS queues than worker threads, the number of workers is reduced to match the number of RSS queues.

**Drop rate estimation**
The module calculates the packet drop rate using the formula: `drop_rate = capture.kernel_drops / (capture.kernel_packets + capture.kernel_drops) * 100`. If the drop rate exceeds 1%, the configuration is marked as unsuccessful.

**CPU cores estimation**

The calculation formula is:
```
throughput_per_core = (decoder.pkts / cpu_usage) × 0.60
required_cores = ceil((total_kernel_packets / throughput_per_core) × 1.5)
```
where:
- `decoder.pkts` – successfully decoded packets per worker thread (**averaged** across all measurements and worker cores).
- `capture.kernel_packets` – packets captured from kernel.
- `capture.kernel_drops` – packets dropped by kernel.
- `total_kernel_packets` = `capture.kernel_packets` + `capture.kernel_drops` (**maximum** value observed during preconfiguration).
- `cpu_usage` – per-thread CPU consumption (**averaged** across all measurements).
- **0.60** represents the target 60% CPU utilization per core (conservative threshold).
- **1.5** is the safety multiplier (`CPU_MULTIPLIER`) to account for uneven traffic distribution.

> [!NOTE]
> A minimum of 4 logical cores is enforced due to performance degradation observed with fewer cores during testing.


### Memory usage

The Memory usage module is responsible for configuring memory settings in Suricata. This includes components such as IPpair, host, defragmentation, stream, and reassembly.


**Configured sections**
- **IPpair** – hash size, prealloc, memcap parameters.
- **host** – hash size, prealloc, memcap parameters.
- **defragmentation** – memcap, hash size, trackers, max-frags, prealloc (`yes`) parameters.
- **stream** – memcap, prealloc-sessions parameters.
- **reassembly** – memcap, segment-prealloc parameters.

**Warning counters**

The module monitors the following counters:
- `ippair_memuse` / `ippair_memcap` / `host_memuse` / `host_memcap` – Warns when `memuse / memcap ≥ 0.95` (memory usage reaches 95% of configured memcap).
- `defrag_max_frags_reached` / `defrag_max_trackers_reached` / `defrag_tracker_hard_reuse` – configuration fails if non-zero (insufficient defragmentation memory).
- `tcp_ssn_memcap_drop` / `tcp_segment_memcap_drop` – configuration fails if non-zero (insufficient stream/reassembly memory).
- `tcp_reassembly_gap` – warning if non-zero (TCP stream gaps detected).
- `tcp_pkt_on_wrong_thread` – warning if non-zero (poor load balancing across threads).

**Hash size**

The sizes of the hash tables are determined based on the maximum observed values of counters:
- **IPpair** – `ippair_active` (maximum number of active IPpair objects).
- **Host** – `host_active` (maximum number of active host objects).
- **Defragmentation** – `defrag_tracker_active` (maximum number of active defrag trackers). This counter also  sets `trackers` parameter in defragmentation section. 

These values are rounded up to the next higher power of two.

**Prealloc**

Preallocated objects depend on the maximum number of active objects:
- **IPpair / Host** – `ippair_active` / `host_active` → prealloc = max_active / 2
- **Defragmentation** – `defrag_tracker_active` → prealloc = max_active / 2
- **max-frags** – calculated as `defrag_tracker_active` × `defrag_max_fragments`


**Memory estimation:**
Memory usage estimation is calculated as:
```
M = B · Sb + (Omax_active + Oprealloc · 1.2) · So
```
Where:
- B = number of buckets
- Sb = size of a single bucket structure
- Omax_active = maximum number of active objects
- Oprealloc = amount of preallocation
- So = size of the object structure

### Flow

The Flow module in Suricata configures how Suricata tracks and manages network flows. It controls how much memory is allocated for flow tracking (memcap), the size of the hash table (hash-size), and how many flow objects are preallocated (prealloc).

**Configured parameters:**
- `memcap` – Memory limit for flow tracking
- `hash-size` – Size of the flow hash table
- `prealloc` – Number of preallocated flow objects
- `managers` – Number of flow manager threads
- `recyclers` – Number of flow recycler threads

**Hash size:**
The size of the hash table is configured based on:
1. **Sweep Line algorithm** – Estimates the number of flows that are active simultaneously at any point during the measurement period
2. **Load factor** – Monitored during each iteration. If the load factor exceeds a threshold (α > 2), the hash table is expanded. If it falls below 25% of αmax, the table size is reduced
3. **Collision analysis** – If the ratio between the maximum and the average number of flows in a bucket exceeds 3, the hash table is considered insufficiently sized

The resulting value is rounded to the nearest power of two, ensuring an efficient hash distribution.

**Prealloc:**
The number of preallocated objects is set to half of the maximum observed number of active flows, based on the maximum value of the `flow.active` counter.

**Memcap:**
The total memory consumption is calculated as:
```
M = B · Sb + ((Fmax_active + Fprealloc · 1.2) + T · P) · Sf
```
Where:
- B = number of buckets
- Sb = size of a flow bucket structure
- Fmax_active = maximum value of the flow.active counter
- Fprealloc = number of preallocated flow objects
- T = number of worker threads
- P = locally preallocated pool of flow objects per thread (200)
- Sf = size of the flow object structure

### Flow threads

The Flow threads module configures management threads in a way that prevents them from becoming a bottleneck for packet loss. The module specifies the number of threads responsible for management and cleanup (manager and recycler threads). Robust regression is used to estimate the number of required threads.

**Manager threads**

The manager thread is primarily responsible for inspecting flows in the flow table and performing evictions when necessary. Its workload is monitored by the global counter `flow.mgr_full_hash_pass`, which represents the total number of passes through the hash table.

Flow managers are considered overloaded **only when both conditions are met simultaneously and persist for a sustained period (6 minutes)**:
- overall average CPU usage exceeds 95.0%
- The slope (full hash table passes per second) falls below 0.1, indicating that the managers cannot complete a full pass within the required 10 seconds interval

The number of manager threads is adjusted based on their observed performance during measurement.

**Recycler threads**

The recycler thread cleans flows from the queue and returns them to the pool. The queue size is estimated using the `flow.recycler.queue_avg` counter.

Recyclers are considered overloaded **only when both conditions are met simultaneously**:
- Overall average CPU usage of the recycler threads exceeds 95.0%
- The queue size shows a consistent increasing trend across all subwindows

The number of recycler threads is adjusted based on their observed performance, with the goal of ensuring that they can clean flows efficiently and prevent the growth of their queue.
