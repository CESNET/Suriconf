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
The first stage performs a Suricata preconfiguration run on a defined network interface. During this run, the system collects performance data about the system that will be configured, such as CPU core load, and saves logs about the observed network traffic. Every five seconds, it collects and stores samples. 

### Query and Execute stage
This stage serves as the primary interface for communication between Suriconf and its modules. During this phase, the system interacts with individual modules to retrieve their calculated configurations and writes them to the resulting Suricata configuration file.

The Query and Execute stage sorts the modules based on configuration dependencies:

1. **Flow threads** – specifies the number of management threads (recycler and manager threads).
2. **CPU affinity** – assignment of CPU cores to worker threads.
3. **Flow** – sets flow memcap, flow hash size and number of preallocated flow objects.
4. **Memory usage** – specifies memcaps and controls limits of memory (stream, reassembly, IPpair, defragmentation, host settings).

This ordering is critical. For example, the number of CPU cores must be determined before initializing the Flow module, since its memcap must provide sufficient memory for preallocated flow objects for each thread.

## Modules

### CPU affinity

The CPU affinity module configures the number of worker threads and defines the logical CPU cores to which they are pinned (a single worker is exclusively assigned to a specific logical core with the highest priority).

**Preconfiguration run**

During the preconfiguration run, Suricata workers use logical cores that are specified in the configuration file vector and are not utilized by other threads (management), with the maximum number limited by the available RX RSS queues. All CPU affinity settings are applied in this stage for better performance estimation, except for NUMA locality determination, since all cores are running and no selection is needed.

**Responsibilities**

- Detects which network interface is associated with each NUMA node and attempts to use CPU cores from the corresponding node to take advantage of NUMA locality.
- Uses the `ethtool` tool to configure RSS (Receive Side Scaling) and AF_PACKET affinity.
- Assigns the appropriate IRQs to each core (each core is assigned to a single RSS queue).
- Disables hardware offloading features.
- If there are fewer RSS queues than worker threads, the number of workers is reduced to match the number of RSS queues.

**Drop rate estimation**

The module calculates the packet drop rate using the formula:
```
drop_rate = capture.kernel_drops / (capture.kernel_packets + capture.kernel_drops) * 100
```
If the drop rate exceeds 1%, the configuration is marked as unsuccessful.

**CPU cores estimation**

The calculation formula is:
```
throughput_per_core = (decoder.pkts / cpu_usage) × 0.50
required_cores = ceil((total_kernel_packets / throughput_per_core) × 1.5)
```
where:
- `decoder.pkts` – successfully decoded packets per worker thread (**averaged** across all measurements and worker cores).
- `capture.kernel_packets` – packets captured from kernel.
- `capture.kernel_drops` – packets dropped by kernel.
- total_kernel_packets = `capture.kernel_packets` + `capture.kernel_drops` (**maximum** value observed during preconfiguration).
- cpu_usage – per-thread CPU consumption (**averaged** across all measurements).
- **0.50** - the target 50% CPU utilization per core (conservative threshold).
- **1.5** - the safety multiplier to account for uneven traffic distribution.

### Memory usage

The Memory usage module is responsible for configuring memory settings in Suricata.

**Responsibilities**

Suriconf configures these sections:
- **IPpair** – `hash-size`, `prealloc`, `memcap` parameters.
- **host** – `hash-size`, `prealloc`, `memcap` parameters.
- **defragmentation** – `memcap`, `hash-size`, `trackers`, `max-frags`, `prealloc` (`yes`) parameters.
- **stream** – `memcap`, `prealloc-sessions` parameters.
- **reassembly** – `memcap`, `segment-prealloc` parameters.

**Warning counters**

The module monitors the following counters:
- `ippair_memuse`, `ippair_memcap`, `host_memuse`, `host_memcap` – warns when `memuse / memcap ≥ 0.95` (memory usage reaches 95% of configured memcap).
- `defrag_max_frags_reached`, `defrag_max_trackers_reached`, `defrag_tracker_hard_reuse` – configuration fails if non-zero (insufficient defragmentation memory).
- `tcp_ssn_memcap_drop`, `tcp_segment_memcap_drop` – configuration fails if non-zero (insufficient stream/reassembly memory).
- `tcp_reassembly_gap` – warning if non-zero (TCP stream gaps detected).
- `tcp_pkt_on_wrong_thread` – warning if non-zero (poor load balancing across threads).


**Hash size (IPpair, host, defragmentation)**

The sizes of the hash tables are determined based on the maximum observed values of counters:
- **IPpair** – `ippair_active` (maximum number of active IPpair objects).
- **host** – `host_active` (maximum number of active host objects).
- **defragmentation** – `defrag_tracker_active` (maximum number of active defrag trackers). This counter also sets `trackers` parameter in defragmentation section. 

These values are rounded up to the next higher power of two, ensuring an efficient hash distribution.

**Prealloc (IPpair, host, defragmentation)**

Preallocated objects depend on the maximum number of active objects:
- **IPpair / host** – `ippair_active` / `host_active` → prealloc = max_active / 2.
- **defragmentation** – `defrag_tracker_active` → prealloc = max_active / 2.
- `max-frags` – calculated as `defrag_tracker_active` × `defrag_max_fragments`.


**Memory estimation (IPpair, host, defragmentation)**

Memory usage estimation is calculated as:
```
M = B * Sb + (Omax_active + Oprealloc * 1.2) * So
```
where:
- B - number of buckets.
- Sb - size of a single bucket structure.
- Omax_active - maximum number of active objects.
- Oprealloc - amount of preallocation.
- So - size of the object structure.
- 1.2 - safety margin.

**Stream**

Stream memory is sized per TCP session. Parameter `prealloc-sessions` is distributed across worker threads:

```
prealloc-sessions = (max_tcp_active_sessions / 2) / workers
stream_memcap = (max_tcp_active_sessions + prealloc-sessions * workers * 1.2) * TCP_session_structures
```
- max_tcp_active_sessions – max `tcp.active_sessions`.
- `prealloc-sessions` – preallocation per worker.
- workers – number of new worker threads.
- 1.2 – safety margin.

**Reassembly**

Reassembly memory has two components: packet data buffered per segment and segment metadata structures. Parameter `segment-prealloc` is distributed across worker threads:

```
segment-prealloc = (max_tcp_active_segments / 2) / workers
reassembly_memcap = (max_tcp_active_segments + segment-prealloc * workers) * (packet_overhead + TCP_segment_structure)
```
- max_tcp_active_segments – max `tcp.active_segments`.
- `segment-prealloc` – preallocation per worker.
- workers – number of new worker threads.
- packet_overhead – estimated packet data size per segment.

The packet_overhead is the packet data per segment excluding segment structures, derived per sample from measurements:
```
packet_overhead = (reassembly_memuse - (segment-prealloc * workers + tcp.active_segments) * TCP_segment_structure) / tcp.active_segments
```
The maximum packet_overhead across all samples is used.

**Default values**

These default values are used when the maximum number of active objects does not exceed the active limit threshold. The default hash table size, max TCP active sessions, and segments is 512, the default preallocation is 256 objects, and the default maximum number of fragments per packet is 4. The default packet size is 1500 (the MTU).

### Flow

The Flow module in Suricata configures how Suricata tracks and manages network flows. 

**Responsibilities**

Suriconf configures these parameters in the flow section:
- `memcap`  – memory limit for flow tracking.
- `hash-size` – size of the flow hash table.
- `prealloc` – number of preallocated flow objects.

**Hash size**

The size of the hash table is configured based on:
1. **Sweep Line algorithm** – estimates the number of flows that are active simultaneously at any point during the measurement period.
2. **Collision analysis** – if the ratio between the maximum and average number of flows in a bucket (computed across a 5-sample window (25 seconds)) exceeds 3, the hash table is expanded. 
3. **Load factor** – monitored during each window. If the load factor exceeds a threshold (𝛼 > 2), the hash table is expanded. If the maximum observed load factor falls below 25% of 𝛼_𝑚𝑎𝑥 (where 𝛼_𝑚𝑎𝑥 = 2), the table size is reduced to improve memory efficiency.

If the table size is reduced or expanded, the resulting hash size is the maximum observed number of active flows up to the next higher power of two.

**Prealloc**

The number of preallocated objects is set to half of the maximum observed number of active flows, based on the maximum value of the `flow.active` counter.

**Memcap**

The total memory consumption is calculated as:
```
M = B * Sb + ((Fmax_active + Fprealloc * 1.2) + T * P) * Sf
```
where:
- B - number of buckets.
- Sb - size of a flow bucket structure.
- Fmax_active - maximum value of the `flow.active` counter.
- Fprealloc - number of preallocated flow objects.
- 1.2 - safety margin.
- T - number of worker threads.
- P - locally preallocated pool of flow objects per thread (200).
- Sf - size of the flow object structure.

### Flow threads

The Flow threads module configures management threads in a way that prevents them from becoming a bottleneck for packet loss. 

**Responsibilities**

Suriconf estimates:
- number of manager threads.
- number of recycler threads.

Each thread runs on its own dedicated logical core. Robust regression is used to estimate the number of required threads.

**Manager threads**

The manager threads are primarily responsible for inspecting flows in the flow table and performing evictions when necessary. Their workload is monitored by the global counter `flow.mgr_full_hash_pass`, which represents the total number of passes through the hash table.

Flow managers are considered overloaded **only when both conditions are met simultaneously and persist for a sustained period (6 minutes)**:
- Overall average CPU usage of the manager threads exceeds 95.0%.
- The slope (full hash table passes per second estimated using robust regression) falls below 0.1, indicating that the managers cannot complete a full pass within the required 10 seconds interval.

If overload is detected, the number of manager threads is adjusted based on their observed performance during measurement to ensure they complete a full hash table inspection every 10 seconds.

**Recycler threads**

The recycler threads clean flows from the queue and return them to the pool. The queue size is estimated using the `flow.recycler.queue_avg` counter.

Recyclers are considered overloaded **only when both conditions are met simultaneously and persist for a sustained period (6 minutes)**:
- Overall average CPU usage of the recycler threads exceeds 95.0%.
- The queue size shows a consistent increasing trend. 

If overload is detected, the number of recycler threads is increased based on their observed performance, ensuring efficient flow cleanup and preventing queue growth.