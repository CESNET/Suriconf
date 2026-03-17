use std::path::PathBuf;
extern crate chrono;
use chrono::offset::Utc;
use chrono::DateTime;
use std::time::{SystemTime};
use std::fs;
use crossbeam_channel::{bounded, Receiver};
use signal_hook::consts::signal::SIGINT;
use signal_hook::iterator::Signals;
use std::thread;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use strum_macros::{Display, EnumIter};
use sysinfo::System;
use crate::flow::FlowModule;
use clap::{ValueEnum};
pub enum Reason {
    timeout,
    shutdown,
    forced,
    emergency,
    tcp_reuse // TODO, in future think about tcp_reuse
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CaptureMode {
    DPDK,
    AF_PACKET
}

impl Default for CaptureMode {
    fn default() -> Self { CaptureMode::AF_PACKET }
}

impl Reason {
    pub fn new(key_str: &str) -> Self {
        match key_str {
            "timeout" => Reason::timeout,
            "shutdown" => Reason::shutdown,
            "forced" => Reason::forced,
            "emergency" => Reason::emergency,
            "tcp_reuse" => Reason::tcp_reuse,
            _ => panic!("Unable to convert key string slice.")
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Answer<'a>{
    pub key: &'a Keys,
    pub value: &'a Value
}

pub struct Change {
    pub keys: Keys,
    pub value: Value
}
impl Change {
    pub fn collect_changes(table: &HashMap<Keys, Value>) -> Vec<Change> {
        table.iter().filter_map(|(k, v)| { if !v.is_null() { Some(Change { keys: *k, value: v.clone() }) } else { None } }).collect()
    }
}

#[derive(PartialEq, Eq)]
pub enum SuricataAgain {
    Done,
    RunAgain
}

#[derive(PartialEq, Debug)]
pub enum RobRegression{
    Huber,
    TheilSen
}

pub enum ModuleResult {
    Up,
    Ok,
    Down
}

#[derive(Default, Debug)]
pub struct SystemVar {
    pub sys: System,
    pub threads: Vec<Thread>
}

#[derive(Deserialize, Serialize, PartialEq, Default, Debug)]
pub struct Thread {
    pub name: Vec<String>,
    pub core_id: u32,
    pub cpu_usage: Vec<f32>
}

#[derive(Serialize, Debug, Default)]
pub struct Threads {
    pub workers: Vec<u64>,
    pub management: Vec<u64>,
}

#[derive(Debug, Default)]
pub struct JsonVar {
    pub var_index: HashMap<Keys, Value>
}

pub trait Module {

    fn new(analysis: &Analysis, debug: bool) -> Self where Self: Sized;

    fn questions(&self) -> &HashMap<Keys, Value>;
    fn init_questions(&self) -> Vec<Keys> {
        self.questions().keys().copied().collect()
    }
    fn main(&mut self, answers: &Vec<Answer<'_>>) -> Vec<Change>;

    fn not_enough_memory(&mut self, answers: &Vec<Answer<'_>>) -> bool {
        answers.iter().find(|a| a.key == &Keys::max_memory_usage).expect("Unable to get max max_memory_usage.").value.as_u64().expect("Unable to transform max_memory_usage to u64.");
        // TODO, modul v sobe musi obsahovat vsechny dotazy
        false
    }

    fn memcap_pressure(&mut self, answers: &Vec<Answer<'_>>) {
        todo!()
    }
}

pub fn create_module(name: &str, analysis: &Analysis, debug: bool) -> Box<dyn Module> {
    match name {
        "flow" => Box::new(FlowModule::new(analysis, debug)),
        _ => panic!("Unknown module."),
    }
}
pub struct CreatedLogs {
    pub suri_configuration: PathBuf,
    pub stats: PathBuf,
    pub flows: PathBuf,
    pub preconfiguration: PathBuf,
}

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum Keys { // JUST FOR FLOW
    max_memory_usage,
    wrk_cpu_set,
    max_cpu_usage_vec,
    threads_stat,
    uptime,
    memcap_pressure,
    memcap_pressure_max,
    flow_memcap,
    flow_memuse,
    flow_active,
    flow_hashsize,
    flow_prealloc,
    flow_managers,
    flow_recyclers,
    flow_set, // set of flows for analysis
    flow_mgr_full_hash_pass,
    flow_mgr_rows_maxlen,
    flow_mgr_flows_checked,
    flow_rc_queue_avg,
    flow_rc_recycled,
    flow_emergency_recovery,
    flow_emerg_mode_entered,
    flow_emerg_mode_over,
    flow_wrk_spare_sync_avg,
    flow_wrk_spare_sync_empty,
    flow_wrk_spare_sync_incomplete,
    flow_timeouts_def_new,
    flow_timeouts_def_estab,
    flow_timeouts_def_closed,
    flow_timeouts_def_bypass,
    flow_timeouts_def_em_new,
    flow_timeouts_def_em_estab,
    flow_timeouts_def_em_closed,
    flow_timeouts_def_em_bypass,
    flow_timeouts_tcp_new,
    flow_timeouts_tcp_estab,
    flow_timeouts_tcp_closed,
    flow_timeouts_tcp_bypass,
    flow_timeouts_tcp_em_new,
    flow_timeouts_tcp_em_estab,
    flow_timeouts_tcp_em_closed,
    flow_timeouts_tcp_em_bypass,
    flow_timeouts_udp_new,
    flow_timeouts_udp_estab,
    flow_timeouts_udp_bypass,
    flow_timeouts_udp_em_new,
    flow_timeouts_udp_em_estab,
    flow_timeouts_udp_em_bypass,
    flow_timeouts_icmp_new,
    flow_timeouts_icmp_estab,
    flow_timeouts_icmp_bypass,
    flow_timeouts_icmp_em_new,
    flow_timeouts_icmp_em_estab,
    flow_timeouts_icmp_em_bypass
}

impl Keys {
    pub fn new(key_str: &str) -> Self {
        match key_str {
            "max_memory_usage" => Keys::max_memory_usage,
            "wrk_cpu_set" => Keys::wrk_cpu_set,
            "max_cpu_usage_vec" => Keys::max_cpu_usage_vec, 
            "threads_stat" => Keys::threads_stat,
            "uptime" => Keys::uptime,
            "memcap_pressure" => Keys::memcap_pressure,
            "memcap_pressure_max" => Keys::memcap_pressure_max,
            "flow_memcap" => Keys::flow_memcap,
            "flow_memuse" => Keys::flow_memuse,
            "flow_active" => Keys::flow_active,
            "flow_hashsize" => Keys::flow_hashsize,
            "flow_prealloc"=> Keys::flow_prealloc,
            "flow_managers" => Keys::flow_managers,
            "flow_recyclers" => Keys::flow_recyclers,
            "flow_set" => Keys::flow_set,
            "flow_mgr_full_hash_pass" => Keys::flow_mgr_full_hash_pass,
            "flow_mgr_rows_maxlen" => Keys::flow_mgr_rows_maxlen,
            "flow_mgr_flows_checked" => Keys::flow_mgr_flows_checked,
            "flow_rc_queue_avg" => Keys::flow_rc_queue_avg,
            "flow_rc_recycled" => Keys::flow_rc_recycled,
            "flow_emergency_recovery" => Keys::flow_emergency_recovery,
            "flow_emerg_mode_entered" => Keys::flow_emerg_mode_entered,
            "flow_emerg_mode_over" => Keys::flow_emerg_mode_over,
            "flow_wrk_spare_sync_avg" => Keys::flow_wrk_spare_sync_avg,
            "flow_wrk_spare_sync_empty" => Keys::flow_wrk_spare_sync_empty,
            "flow_wrk_spare_sync_incomplete" => Keys::flow_wrk_spare_sync_incomplete,
            "flow_timeouts_def_new" => Keys::flow_timeouts_def_new,
            "flow_timeouts_def_estab" => Keys::flow_timeouts_def_estab,
            "flow_timeouts_def_closed" => Keys::flow_timeouts_def_closed,
            "flow_timeouts_def_bypass" => Keys::flow_timeouts_def_bypass,
            "flow_timeouts_def_em_new" => Keys::flow_timeouts_def_em_new,
            "flow_timeouts_def_em_estab" => Keys::flow_timeouts_def_em_estab,
            "flow_timeouts_def_em_closed" => Keys::flow_timeouts_def_em_closed,
            "flow_timeouts_def_em_bypass" => Keys::flow_timeouts_def_em_bypass,
            "flow_timeouts_tcp_new" => Keys::flow_timeouts_tcp_new,
            "flow_timeouts_tcp_estab" => Keys::flow_timeouts_tcp_estab,
            "flow_timeouts_tcp_closed" => Keys::flow_timeouts_tcp_closed,
            "flow_timeouts_tcp_bypass" => Keys::flow_timeouts_tcp_bypass,
            "flow_timeouts_tcp_em_new" => Keys::flow_timeouts_tcp_em_new,
            "flow_timeouts_tcp_em_estab" => Keys::flow_timeouts_tcp_em_estab,
            "flow_timeouts_tcp_em_closed" => Keys::flow_timeouts_tcp_em_closed,
            "flow_timeouts_tcp_em_bypass" => Keys::flow_timeouts_tcp_em_bypass,
            "flow_timeouts_udp_new" => Keys::flow_timeouts_udp_new,
            "flow_timeouts_udp_estab" => Keys::flow_timeouts_udp_estab,
            "flow_timeouts_udp_bypass" => Keys::flow_timeouts_udp_bypass,
            "flow_timeouts_udp_em_new" => Keys::flow_timeouts_udp_em_new,
            "flow_timeouts_udp_em_estab" => Keys::flow_timeouts_udp_em_estab,
            "flow_timeouts_udp_em_bypass" => Keys::flow_timeouts_udp_em_bypass,
            "flow_timeouts_icmp_new" => Keys::flow_timeouts_icmp_new,
            "flow_timeouts_icmp_estab" => Keys::flow_timeouts_icmp_estab,
            "flow_timeouts_icmp_bypass" => Keys::flow_timeouts_icmp_bypass,
            "flow_timeouts_icmp_em_new" => Keys::flow_timeouts_icmp_em_new,
            "flow_timeouts_icmp_em_estab" => Keys::flow_timeouts_icmp_em_estab,
            "flow_timeouts_icmp_em_bypass" => Keys::flow_timeouts_icmp_em_bypass,
            _ => panic!("Unable to convert key string slice.")
        }
    }

}

#[derive(EnumIter, Debug, Display,PartialEq, Eq, Copy, Clone)]
pub enum FileNames {
    suricata,
    suriconf,
    preconf
}
impl CreatedLogs {
    pub fn new(log_dir: &PathBuf) -> Self {
        let system_time = SystemTime::now();
        let datetime: DateTime<Utc> = system_time.into();

        let mut suri_configuration = PathBuf::from("./tmp");
        if !suri_configuration.exists() {
            fs::create_dir_all(&suri_configuration).expect("Unable to create tmp directory.");
        }

        let mut stats =log_dir.clone();
        stats.push("stats.json");

        let mut flows =log_dir.clone();
        flows.push("flows.json");

        let mut preconfiguration = PathBuf::from("./tmp");

        suri_configuration.push(format!("suricata{}.yaml", datetime.format("-%Y-%m-%d-%H:%M:%S")));
        preconfiguration.push(format!("preconfiguration{}.json", datetime.format("-%Y-%m-%d-%H:%M:%S")));
        Self {
            suri_configuration,
            stats,
            flows,
            preconfiguration
        }
    }
}
#[derive(Eq, Hash, PartialEq, Serialize, Debug)]
pub enum Protocols {
    Transport(TrasportProtocols),
    AppLayer(AppLayerProtocols)
}

#[derive(Eq, Hash, PartialEq, Serialize, Debug)]
pub enum AppLayerProtocols {
    FAILED_TCP,
    HTTP,
    FTP,
    SMTP,
    TLS,
    SSH,
    IMAP,
    SMB,
    DCERPC_TCP,
    DNS_TCP,
    NFS_TCP,
    NTP,
    FTP_DATA,
    TFTP,
    IKE,
    KRB5_TCP,
    QUIC,
    DHCP,
    SIP_TCP,
    RFB,
    MQTT,
    TELNET,
    WEBSOCKET,
    LDAP_TCP,
    DOH2,
    RDP,
    HTTP2,
    BITTORRENT_DHT,
    POP3,
    MDNS,
    SNMP,
    FAILED_UDP,
    DCERPC_UDP,
    DNS_UDP,
    NFS_UDP,
    KRB5_UDP,
    SIP_UDP,
    LDAP_UDP,
    DNS
}

impl AppLayerProtocols {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "failed_tcp" => Some(Self::FAILED_TCP),
            "http" => Some(Self::HTTP),
            "ftp" => Some(Self::FTP),
            "smtp" => Some(Self::SMTP),
            "tls" => Some(Self::TLS),
            "ssh" => Some(Self::SSH),
            "imap" => Some(Self::IMAP),
            "smb" => Some(Self::SMB),
            "dcerpc_tcp" => Some(Self::DCERPC_TCP),
            "dns_tcp" => Some(Self::DNS_TCP),
            "nfs_tcp" => Some(Self::NFS_TCP),
            "ntp" => Some(Self::NTP),
            "ftp-data" => Some(Self::FTP_DATA),
            "tftp" => Some(Self::TFTP),
            "ike" => Some(Self::IKE),
            "krb5_tcp" => Some(Self::KRB5_TCP),
            "quic" => Some(Self::QUIC),
            "dhcp" => Some(Self::DHCP),
            "sip_tcp" => Some(Self::SIP_TCP),
            "rfb" => Some(Self::RFB),
            "mqtt" => Some(Self::MQTT),
            "telnet" => Some(Self::TELNET),
            "websocket" => Some(Self::WEBSOCKET),
            "ldap_tcp" => Some(Self::LDAP_TCP),
            "doh2" => Some(Self::DOH2),
            "rdp" => Some(Self::RDP),
            "http2" => Some(Self::HTTP2),
            "bittorrent-dht" => Some(Self::BITTORRENT_DHT),
            "pop3" => Some(Self::POP3),
            "mdns" => Some(Self::MDNS),
            "snmp" => Some(Self::SNMP),
            "failed_udp" => Some(Self::FAILED_UDP),
            "dcerpc_udp" => Some(Self::DCERPC_UDP),
            "dns_udp" => Some(Self::DNS_UDP),
            "nfs_udp" => Some(Self::NFS_UDP),
            "krb5_udp" => Some(Self::KRB5_UDP),
            "sip_udp" => Some(Self::SIP_UDP),
            "ldap_udp" => Some(Self::LDAP_UDP),
            "dns" => Some(Self::DNS),
            _ => None,
        }
    }
}
#[derive(Eq, Hash, PartialEq, Serialize, Debug)]
pub enum TrasportProtocols {
    TCP,
    UDP
}

impl TrasportProtocols {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::TCP),
            "udp" => Some(Self::UDP),
            _ => None
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    AskModify,
    ForceModify,
    Suggestion
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Suggestion
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Analysis {
    Static,
    Dynamic
}

impl Default for Analysis {
    fn default() -> Self {
        Analysis::Static
    }
}

pub fn ctrl_channel() -> Result<Receiver<()>> {
    let (sender, receiver) = bounded(100);
    let mut signals = Signals::new([SIGINT])?;

    thread::spawn(move || {
        for _ in signals.forever() {
            let _ = sender.send(());
        }
    });
    Ok(receiver)
}