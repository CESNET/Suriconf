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
use serde::Serialize;

pub struct CreatedLogs {
    pub suri_configuration: PathBuf,
    pub stats: PathBuf,
    pub flows: PathBuf,
    pub preconfiguration: PathBuf,
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