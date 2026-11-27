/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>
Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

This file defines constats for Suriconf.
*/

use crate::memory_usage::{DefaultPacketSize, MaxPendingPackets};
use crate::structures::RobRegression;

pub mod argument;
pub mod config_gen;
pub mod cpu_affinity;
pub mod flow;
pub mod flow_threads;
pub mod json;
pub mod memory_usage;
pub mod module;
pub mod query;
pub mod regression;
pub mod structures;
pub mod suricata;
pub mod suricata_tun;
pub mod yaml;

const DEFAULT_CONFIG: &str = include_str!("../suriconf.yaml");

const FLOW_WINDOW: u64 = 5; // in seconds
const MIN_RUN: u64 = 360;
const WINDOWS: u64 = 3;
const ACTIVE_LIMIT: u64 = 512;
const FRAGMENTS: f64 = 4.0;
const MTU: u64 = 1500;

// Suricata structures
const FLOW_BUCKET: f64 = 64.0; // 64B arch linux, arch:x86
const FLOW_OBJECT: f64 = 312.0; // 296 B for flow object // reality 272 B
const PACKET: f64 = 464.0;
const HOST_HASHROW: f64 = 64.0;
const IPPAIR_HASHROW: f64 = 64.0;
const DEFRAG_TRACKER_HASHROW: f64 = 48.0;
const HOST_OBJECT: f64 = 120.0; // prealloc
const IPPAIR_OBJECT: f64 = 136.0;
const DEFRAG_TRACKER: f64 = 144.0;
const TCP_SESSION: f64 = 304.0;
const TCP_STATE_QUEUE: f64 = 32.0 * 5.0; // reserve 5x for retransmission
const STREAM_TCP_SACK_RECORD: f64 = 40.0 * 10.0; // reserve 10x for retransmission
const TCP_SEGMENT: i64 = 56;

const LOAD_FACTOR: f64 = 2f64;
const MAX_AVG_RATIO: i64 = 3;
const MIN_AVG_RATIO: f64 = 0.5;
const RECYCLER_START: u8 = 1;
const MANAGER_START: u8 = 1;
const SYNC_AVG: u64 = 100;
const MULTIPLIER: f64 = 1.2;

const CPU_MULTIPLIER: f64 = 1.5;
const FLOW_LOCAL_THREAD_MAX: f64 = 200.0;

const ROB_REGRESSION: RobRegression = RobRegression::Huber;
const MAX_PENDING_PACKETS: MaxPendingPackets = MaxPendingPackets::forthy_five_thousand;
const DEFAULT_PACKET_SIZE: DefaultPacketSize = DefaultPacketSize::Average;

const CPU_USAGE_MAX: f32 = 95.0;

const CPU_USAGE: f64 = 60.0;
const HUBER_THRESHOLD: f64 = 0.0;
const MANAGER_SLOPE: f64 = 0.1; // once every 10 s
const PANIC_THRESHOLD: u64 = 100;
