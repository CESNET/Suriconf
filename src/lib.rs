use crate::structures::RobRegression;

macro_rules! mods {
    ($($name:ident),*) => {
        $(pub mod $name;)*
    };
}

mods!(argument, structures, yaml, suricata, json, test_cpu_affinity,
    memory_usage, capture_mode, query, flow, regression);

static FLOW_WINDOW: u64 = 5; // in seconds
static MIN_RUN: u64 = 120;
static WINDOWS:u64 = 3;
static FLOW_BUCKET: f64 = 64.0; // 64B arch linux, arch:x86
static FLOW_OBJECT: f64 = 296.0; // 296 B for flow object
static LOAD_FACTOR: f64 = 3f64;
static MAX_AVG_RATIO: i64 = 3;
static MIN_AVG_RATIO: f64 = 0.25;
static RECYCLER_START: u8 = 1;
static  MANAGER_START: u8 = 1;
static SYNC_AVG: u64 = 100;

static FLOW_LOCAL_THREAD_MAX: f64 = 200.0;

static ROB_REGRESSION: RobRegression = RobRegression::Huber;

static CPU_USAGE_MAX: f32 = 95.0;
static HUBER_THRESHOLD: f64 = 0.0;

static MANAGER_SLOPE: f64 = 0.1;  // once every 10 s