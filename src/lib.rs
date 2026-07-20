/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>

This file defines constats for Suriconf.
*/

use crate::memory_usage::{DefaultPacketSize, MaxPendingPackets};
use crate::structures::RobRegression;

macro_rules! mods {
    ($($name:ident),*) => {
        $(pub mod $name;)*
    };
}

mods!(argument, structures, yaml, suricata, json,
    memory_usage, query, flow, flow_threads, regression,
    module, cpu_affinity);

static FLOW_WINDOW: u64 = 5; // in seconds
static MIN_RUN: u64 = 120;
static WINDOWS:u64 = 3;
static ACTIVE_LIMIT: u64 = 512;
static FRAGMENTS: f64 = 4.0;
static MTU: u64 = 1500;

// Suricata structures
static FLOW_BUCKET: f64 = 64.0; // 64B arch linux, arch:x86
static FLOW_OBJECT: f64 = 312.0; // 296 B for flow object // reality 272 B
static PACKET: f64 = 464.0;
static HOST_HASHROW: f64 = 64.0;
static IPPAIR_HASHROW: f64 = 64.0;
static  DEFRAG_TRACKER_HASHROW: f64 = 48.0;
static HOST_OBJECT: f64 = 120.0; // through prealloc
static IPPAIR_OBJECT: f64 = 136.0;
static DEFRAG_TRACKER: f64 = 144.0;
static TCP_SESSION: f64 = 304.0;
static TCP_STATE_QUEUE: f64 = 32.0 * 5.0; // reserve 5x for retransmission
static STREAM_TCP_SACK_RECORD: f64 = 40.0 * 10.0; // reserve 10x for retransmission
static TCP_SEGMENT: i64 = 56;

static LOAD_FACTOR: f64 = 3f64;
static MAX_AVG_RATIO: i64 = 3;
static MIN_AVG_RATIO: f64 = 0.25;
static RECYCLER_START: u8 = 1;
static  MANAGER_START: u8 = 1;
static SYNC_AVG: u64 = 100;
static MULTIPLIER: f64 = 1.2;

static CPU_MULTIPLIER: f64 = 1.5;
static FLOW_LOCAL_THREAD_MAX: f64 = 200.0;

static ROB_REGRESSION: RobRegression = RobRegression::Huber;
static MAX_PENDING_PACKETS: MaxPendingPackets = MaxPendingPackets::forthy_five_thousand;
static DEFAULT_PACKET_SIZE: DefaultPacketSize = DefaultPacketSize::Average;

static CPU_USAGE_MAX: f32 = 95.0;

static  CPU_USAGE: f64 = 50.0;
static HUBER_THRESHOLD: f64 = 0.0;
static MANAGER_SLOPE: f64 = 0.1;  // once every 10 s
static PANIC_THRESHOLD: u64 = 100;