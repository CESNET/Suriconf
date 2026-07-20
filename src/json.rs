/*
Author(s): Eliška Červinková <eliska.cervinkova@cesnet.cz>

This file represents a json parser.
*/

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use serde_json::{Deserializer, Value};
use std::collections::HashMap;
use serde::Serialize;
use chrono::{DateTime, FixedOffset, Utc};
use crate::structures::{AppLayerProtocols, TrasportProtocols, CreatedLogs, Thread, SystemVar};

pub fn open_json(file: &PathBuf) -> Result<BufReader<File>, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    Ok(reader)
}

pub fn json_to_value(json_bufreader: BufReader<File>) -> Result<Value, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_reader(json_bufreader)?;
    Ok(json)
}
pub fn get_the_last_one_stats(json: BufReader<File>) -> Result<Value, Box<dyn std::error::Error>> {
    let stream = Deserializer::from_reader(json).into_iter::<Value>();
    let last = stream.last().ok_or("Empty stream")??;
    Ok(last)
}

pub fn find_in_json_with_path_ref(file_value: &mut Value, path: &str) ->  Value {
     file_value.pointer_mut(path).expect("Unable to find value at path.").clone()
}

pub fn find_in_json_with_path_mut<'a>(file_value: &'a mut Value, path: &str) -> &'a mut Value {
    file_value.pointer_mut(path).expect("Unable to find value at path.")
}

pub fn save_to_json(json: &Value, file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(file)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &json)?;
    Ok(())
}

pub fn check_emergency(stats: &PathBuf) -> bool {
    let stats = match open_json(stats) {
        Err(e) => {panic!("{e}")},
        Ok(stats) => {stats}
    };

    let last_stat = match get_the_last_one_stats(stats) {
        Ok(last_stat) => {last_stat},
        Err(e) => {return false;}
    };

    match find_emerg_mode_entered(&last_stat) {
        Some(result) => {
            result
        },
        None => {false}
    }
}

pub fn find_emerg_mode_entered(stats: &Value) -> Option<bool> {
    let emerg_mode_entered = stats.get("stats").and_then(|h| h.get("flow")
        .and_then(|p| p.get("emerg_mode_entered")).and_then(|p| p.as_u64()))?;
    if emerg_mode_entered > 0 {
        Some(true)
    }
    else {
        Some(false)
    }
}

#[derive(Serialize, Debug, Default)]
pub struct Preconfiguration {
    threads_stat: Vec<Thread>,
    ethtool_stat: Vec<CpuThread>,
    datetime :DateTime<Utc>,
    flow: FlowStructure,
    decoder: DecoderStructure,
    ippair: IPPairStructure,
    host: HostStructure,
    tcp: TCPStructure,
    defrag: DefragStructure,
    uptime: Vec<u64>,
    cpu: CpuStructure,
    memcap_pressure: Vec<u64>,
    memcap_pressure_max: Vec<u64>
}
#[derive(Serialize, Debug, Default)]
pub struct FlowStructure {
    flows: HashMap<String, Vec<Flow>>,
    flow_memuse: Vec<u64>,
    flow_active: Vec<u64>,
    flow_mgr_full_hash_pass: Vec<u64>,
    flow_mgr_rows_maxlen: Vec<u64>,
    flow_mgr_flows_checked: Vec<u64>,
    flow_rc_queue_avg: Vec<u64>,
    flow_rc_recycled: Vec<u64>,
    flow_emerg_mode_over: Vec<u64>,
    flow_emerg_mode_entered: Vec<u64>,
    flow_wrk_spare_sync_avg: Vec<u64>,
    flow_wrk_spare_sync_empty: Vec<u64>,
    flow_wrk_spare_sync_incomplete: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct DecoderStructure {
    avg_pkt_size: Vec<u64>,
    max_pkt_size: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct IPPairStructure {
    ippair_memuse: Vec<u64>,
    ippair_active: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct HostStructure {
    host_memuse: Vec<u64>,
    host_active: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct TCPStructure {
    tcp_active_sessions: Vec<u64>,
    tcp_active_segments: Vec<u64>,
    tcp_ssn_memcap_drop: Vec<u64>,
    tcp_pkt_on_wrong_thread: Vec<u64>,
    tcp_segment_memcap_drop: Vec<u64>,
    tcp_reassembly_gap: Vec<u64>,
    tcp_reassembly_memuse: Vec<u64>,
}

#[derive(Serialize, Debug, Default)]
pub struct DefragStructure {
    defrag_tracker_active: Vec<u64>,
    defrag_max_fragments: Vec<u64>,
    defrag_max_frags_reached: Vec<u64>,
    defrag_max_trackers_reached: Vec<u64>,
    defrag_tracker_hard_reuse: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct CpuStructure {
    capture_kernel_drops: Vec<CpuThread>,
    capture_errors: Vec<CpuThread>,
    capture_kernel_packets: Vec<CpuThread>,
    decoder_pkts: Vec<CpuThread>,
    decoder_invalid: Vec<CpuThread>
}

#[derive(Serialize, Debug, Default)]
pub struct CpuThread {
    pub name: String,
    pub value: Vec<u64>
}

#[derive(Serialize, Debug, Default)]
pub struct Flow {
    flow_id: u64,
    age: u64,
    packets: u64,
    bytes_to_client: u64,
    bytes_to_server: u64,
    start: u64,
    end: u64,
    state: String,
    reason: String,
    proto: String
}

impl Preconfiguration {
    pub fn new(sys: SystemVar, datetime: DateTime<Utc>) -> Self {
        let mut preconf = Self::default();
        preconf.threads_stat = sys.threads;
        preconf.ethtool_stat = sys.ethtool_stat;
        preconf.datetime =  datetime;
        preconf
    }

    pub fn create_preconfiguration_structure_and_save(&mut self, logs: &CreatedLogs) -> Result<(), Box<dyn std::error::Error>> {
        let stats = match open_json(&logs.stats) {
            Ok(stats) => { stats },
            Err(e) => { return Err(e); }
        };

        if let Err(e) = self.get_stats(stats) {
            return Err(e);
        }

        let flows = match open_json(&logs.flows) {
            Ok(flows) => { flows },
            Err(e) => { return Err(e); }
        };

        if let Err(e) = self.get_flows(flows) {
            return Err(e);
        }

        let preconfiguration_to_value = serde_json::to_value(&self)?;

        if let Err(e) = save_to_json(&preconfiguration_to_value, &logs.preconfiguration) {
            return Err(e);
        }

        Ok(())
    }

    pub fn get_stats(&mut self, json: BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
        let stream = Deserializer::from_reader(json).into_iter::<Value>();
        for value in stream {
            match value {
                Ok(value) => {
                    if let None = self.find_uptime(&value) {
                        return Err(Box::from("Unable to parse uptime."))
                    }
                    
                    if let None = self.find_memcap_pressure(&value) {
                        return Err(Box::from("Unable to parse memcap_pressure."))
                    }

                    if let None = self.find_memcap_pressure(&value) {
                        return Err(Box::from("Unable to parse memcap_pressure_max."))
                    }

                    if let None = self.find_flow_memuse(&value) {
                        return Err(Box::from("Unable to parse flow_memuse."))
                    }

                    if let None = self.find_flow_active(&value) {
                        return Err(Box::from("Unable to parse flow_active."))
                    }

                    if let None = self.find_flow_mgr_full_hash_pass(&value) {
                        return Err(Box::from("Unable to parse full_hash_pass."))
                    }

                    if let None = self.find_flow_mgr_rows_maxlen(&value) {
                        return Err(Box::from("Unable to parse mgr_rows_maxlen."))
                    }

                    if let None = self.find_flow_mgr_flows_checked(&value) {
                        return Err(Box::from("Unable to parse flows_checked."))
                    }

                    if let None = self.find_flow_rc_queue_avg(&value) {
                        return Err(Box::from("Unable to parse flow_rc_queue average."))
                    }

                    if let None = self.find_flow_rc_recycled(&value) {
                        return Err(Box::from("Unable to parse  flow_rc_recycled."))
                    }

                    if let None = self.find_flow_emerg_mode_entered(&value) {
                        return Err(Box::from("Unable to parse emerg_mode_entered."))
                    }

                    if let None = self.find_flow_emerg_mode_over(&value) {
                        return Err(Box::from("Unable to parse emerg_mode_over."))
                    }

                    if let None = self.find_flow_wrk_spare_sync_avg(&value) {
                        return Err(Box::from("Unable to parse wrk_spare_sync_avg."))
                    }

                    if let None = self.find_flow_wrk_spare_sync_empty(&value) {
                        return Err(Box::from("Unable to parse wrk_spare_sync_empty."))
                    }

                    if let None = self.find_flow_wrk_spare_sync_incomplete(&value) {
                        return Err(Box::from("Unable to parse wrk_spare_sync_incomplete."))
                    }

                    if let None = self.find_decoder_avg_pkt_size(&value) {
                        return Err(Box::from("Unable to parse avg_pkt_size."))
                    }

                    if let None = self.find_decoder_max_pkt_size(&value) {
                        return Err(Box::from("Unable to parse max_pkt_size."))
                    }

                    if let None = self.find_ippair_memuse(&value) {
                        return Err(Box::from("Unable to parse ippair_memuse."))
                    }

                    if let None = self.find_ippair_active(&value) {
                        return Err(Box::from("Unable to parse ippair_active."))
                    }

                    if let None = self.find_host_memuse(&value) {
                        return Err(Box::from("Unable to parse host_memuse."))
                    }

                    if let None = self.find_host_active(&value) {
                        return Err(Box::from("Unable to parse host_active."))
                    }

                    if let None = self.find_tcp_active_sessions(&value) {
                        return Err(Box::from("Unable to parse tcp_active_sessions."))
                    }

                    if let None = self.find_tcp_active_segments(&value) {
                        return Err(Box::from("Unable to parse tcp_active_segments."))
                    }

                    if let None = self.find_tcp_reassembly_memuse(&value) {
                        return Err(Box::from("Unable to parse reassembly_memuse."))
                    }

                    if let None = self.find_tcp_ssn_memcap_drop(&value) {
                        return Err(Box::from("Unable to parse tcp_ssn_memcap_drop."))
                    }

                    if let None = self.find_tcp_pkt_on_wrong_thread(&value) {
                        return Err(Box::from("Unable to parse tcp_pkt_on_wrong_thread."))
                    }

                    if let None = self.find_tcp_segment_memcap_drop(&value) {
                        return Err(Box::from("Unable to parse tcp_segment_memcap_drop."))
                    }

                    if let None = self.find_tcp_reassembly_gap(&value) {
                        return Err(Box::from("Unable to parse tcp_reassembly_gap."))
                    }

                    if let None = self.find_defrag_tracker_active(&value) {
                        return Err(Box::from("Unable to parse defrag_tracker_active."))
                    }

                    if let None = self.find_defrag_max_fragments(&value) {
                        return Err(Box::from("Unable to parse defrag_max_fragments."))
                    }

                    if let None = self.find_defrag_max_frags_reached(&value) {
                        return Err(Box::from("Unable to parse defrag_max_frags_reached."))
                    }

                    if let None = self.find_defrag_max_trackers_reached(&value) {
                        return Err(Box::from("Unable to parse defrag_max_trackers_reached."))
                    }

                    if let None = self.find_defrag_tracker_hard_reuse(&value) {
                        return Err(Box::from("Unable to parse defrag_tracker_hard_reuse."))
                    }

                    if let None = self.find_capture_kernel_drops(&value) {
                        return Err(Box::from("Unable to parse capture_kernel_drops."))
                    }

                    if let None = self.find_capture_errors(&value) {
                        return Err(Box::from("Unable to parse capture_errors."))
                    }

                    if let None = self.find_capture_kernel_packets(&value) {
                        return Err(Box::from("Unable to parse capture_kernel_packets."))
                    }

                    if let None = self.find_decoder_pkts(&value) {
                        return Err(Box::from("Unable to parse decoder_pkts."))
                    }

                    if let None = self.find_decoder_invalid(&value) {
                        return Err(Box::from("Unable to parse decoder_invalid."))
                    }
                },
                Err(_) => { return Err(Box::from("Unable to parse stats.json.")) }
            }
        }
        Ok(())
    }

    pub fn find_uptime(&mut self, stats: &Value) -> Option<()> {
        self.uptime.push(stats.get("stats").and_then(|s| s.get("uptime"))
            .and_then(|u| u.as_u64())?);
        Some(())
    }
    pub fn find_memcap_pressure(&mut self, stats: &Value) -> Option<()> {
        self.memcap_pressure.push(stats.get("stats").and_then(|h| h.get("memcap")
            .and_then(|p| p.get("pressure")).and_then(|p| p.as_u64()))?);
        Some(())
    }

    pub fn find_memcap_pressure_max(&mut self, stats: &Value) -> Option<()> {
        self.memcap_pressure_max.push(stats.get("stats").and_then(|h| h.get("memcap")
            .and_then(|p| p.get("pressure_max")).and_then(|p| p.as_u64()))?);
        Some(())
    }

    pub fn find_flow_memuse(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_memuse.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("memuse")).and_then(|p| p.as_u64()))?);
        Some(())
    }

    pub fn find_flow_active(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_active.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("active")).and_then(|p| p.as_u64()))?);
        Some(())
    }

    pub fn find_flow_mgr_full_hash_pass(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_mgr_full_hash_pass.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("mgr").and_then(|m| m.get("full_hash_pass")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_mgr_rows_maxlen(&mut self , stats: &Value) -> Option<()> {
        self.flow.flow_mgr_rows_maxlen.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("mgr").and_then(|m| m.get("rows_maxlen")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_mgr_flows_checked(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_mgr_flows_checked.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("mgr").and_then(|m| m.get("flows_checked")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_rc_queue_avg(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_rc_queue_avg.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("recycler").and_then(|m| m.get("queue_avg")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_rc_recycled(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_rc_recycled.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("recycler").and_then(|m| m.get("recycled")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_emerg_mode_entered(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_emerg_mode_entered.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|m| m.get("emerg_mode_entered"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_emerg_mode_over(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_emerg_mode_over.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|m| m.get("emerg_mode_over"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_wrk_spare_sync_avg(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_wrk_spare_sync_avg.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("wrk").and_then(|m| m.get("spare_sync_avg")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_wrk_spare_sync_empty(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_wrk_spare_sync_empty.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("wrk").and_then(|m| m.get("spare_sync_empty")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_flow_wrk_spare_sync_incomplete(&mut self, stats: &Value) -> Option<()> {
        self.flow.flow_wrk_spare_sync_incomplete.push(stats.get("stats").and_then(|h| h.get("flow")
            .and_then(|p| p.get("wrk").and_then(|m| m.get("spare_sync_incomplete")))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_decoder_avg_pkt_size(&mut self, stats: &Value) -> Option<()> {
        self.decoder.avg_pkt_size.push(stats.get("stats").and_then(|h| h.get("decoder").
            and_then(|m| m.get("avg_pkt_size"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_decoder_max_pkt_size(&mut self, stats: &Value) -> Option<()> {
        self.decoder.max_pkt_size.push(stats.get("stats").and_then(|h| h.get("decoder").
            and_then(|m| m.get("max_pkt_size"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_ippair_memuse(&mut self, stats: &Value) -> Option<()> {
        self.ippair.ippair_memuse.push(stats.get("stats").and_then(|h| h.get("ippair").
            and_then(|m| m.get("memuse"))).and_then(|p| p.as_u64())?);
        Some(())
    }
    pub fn find_ippair_active(&mut self, stats: &Value) -> Option<()> {
        self.ippair.ippair_active.push(stats.get("stats").and_then(|h| h.get("ippair").
            and_then(|m| m.get("active"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_host_memuse(&mut self, stats: &Value) -> Option<()> {
        self.host.host_memuse.push(stats.get("stats").and_then(|h| h.get("host").
            and_then(|m| m.get("memuse"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_host_active(&mut self, stats: &Value) -> Option<()> {
        self.host.host_active.push(stats.get("stats").and_then(|h| h.get("host").
            and_then(|m| m.get("active"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_active_sessions(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_active_sessions.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("active_sessions"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_active_segments(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_active_segments.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("reassembly_active_segments"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_reassembly_memuse(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_reassembly_memuse.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("reassembly_memuse"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_ssn_memcap_drop(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_ssn_memcap_drop.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("ssn_memcap_drop"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_pkt_on_wrong_thread(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_pkt_on_wrong_thread.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("pkt_on_wrong_thread"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_segment_memcap_drop(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_segment_memcap_drop.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("segment_memcap_drop"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_tcp_reassembly_gap(&mut self, stats: &Value) -> Option<()> {
        self.tcp.tcp_reassembly_gap.push(stats.get("stats").and_then(|h| h.get("tcp").
            and_then(|m| m.get("reassembly_gap"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_defrag_tracker_active(&mut self, stats: &Value) -> Option<()> {
        self.defrag.defrag_tracker_active.push(stats.get("stats").and_then(|h| h.get("defrag").
            and_then(|m| m.get("tracker_active"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_defrag_max_fragments(&mut self, stats: &Value) -> Option<()> {
        self.defrag.defrag_max_fragments.push(stats.get("stats").and_then(|h| h.get("defrag").
            and_then(|m| m.get("max_fragments"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_defrag_max_frags_reached(&mut self, stats: &Value) -> Option<()> {
        self.defrag.defrag_max_frags_reached.push(stats.get("stats").and_then(|h| h.get("defrag").
            and_then(|m| m.get("max_frags_reached"))).and_then(|p| p.as_u64())?);
        Some(())
    }


    pub fn find_defrag_max_trackers_reached(&mut self, stats: &Value) -> Option<()> {
        self.defrag.defrag_max_trackers_reached.push(stats.get("stats").and_then(|h| h.get("defrag").
            and_then(|m| m.get("max_trackers_reached"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_defrag_tracker_hard_reuse(&mut self, stats: &Value) -> Option<()> {
        self.defrag.defrag_tracker_hard_reuse.push(stats.get("stats").and_then(|h| h.get("defrag").
            and_then(|m| m.get("tracker_hard_reuse"))).and_then(|p| p.as_u64())?);
        Some(())
    }

    pub fn find_capture_kernel_drops(&mut self, stats: &Value) -> Option<()> {
        let threads = stats.get("stats").and_then(|h| h.get("threads"))?.as_object()?;
        for (name, value) in threads {
            if !name.starts_with("W") {
                continue;
            }
            let value = value.get("capture").and_then(|h| h.get("kernel_drops"))?.as_u64()?;
            if let Some(found_thread) = self.cpu.capture_kernel_drops.iter_mut().find(|t| &t.name == name) {
                found_thread.value.push(value)

            } else {
                self.cpu.capture_kernel_drops.push(CpuThread { name: name.to_string(), value: vec![value] })
            }
        }
        Some(())
    }

    pub fn find_capture_errors(&mut self, stats: &Value) -> Option<()> {
        let threads = stats.get("stats").and_then(|h| h.get("threads"))?.as_object()?;
        for (name, value) in threads {
            if !name.starts_with("W") {
                continue;
            }
            let value = value.get("capture").and_then(|h| h.get("errors"))?.as_u64()?;
            if let Some(found_thread) = self.cpu.capture_errors.iter_mut().find(|t| &t.name == name) {
                found_thread.value.push(value)

            } else {
                self.cpu.capture_errors.push(CpuThread { name: name.to_string(), value: vec![value] })
            }
        }
        Some(())
    }

    pub fn find_capture_kernel_packets(&mut self, stats: &Value) -> Option<()> {
        let threads = stats.get("stats").and_then(|h| h.get("threads"))?.as_object()?;
        for (name, value) in threads {
            if !name.starts_with("W") {
                continue;
            }
            let value = value.get("capture").and_then(|h| h.get("kernel_packets"))?.as_u64()?;
            if let Some(found_thread) = self.cpu.capture_kernel_packets.iter_mut().find(|t| &t.name == name) {
                found_thread.value.push(value)

            } else {
                self.cpu.capture_kernel_packets.push(CpuThread { name: name.to_string(), value: vec![value] })
            }
        }
        Some(())
    }

    pub fn find_decoder_pkts(&mut self, stats: &Value) -> Option<()> {
        let threads = stats.get("stats").and_then(|h| h.get("threads"))?.as_object()?;
        for (name, value) in threads {
            if !name.starts_with("W") {
                continue;
            }
            let value = value.get("decoder").and_then(|h| h.get("pkts"))?.as_u64()?;
            if let Some(found_thread) = self.cpu.decoder_pkts.iter_mut().find(|t| &t.name == name) {
                found_thread.value.push(value)

            } else {
                self.cpu.decoder_pkts.push(CpuThread { name: name.to_string(), value: vec![value] })
            }
        }
        Some(())
    }

    pub fn find_decoder_invalid(&mut self, stats: &Value) -> Option<()> {
        let threads = stats.get("stats").and_then(|h| h.get("threads"))?.as_object()?;
        for (name, value) in threads {
            if !name.starts_with("W") {
                continue;
            }
            let value = value.get("decoder").and_then(|h| h.get("invalid"))?.as_u64()?;
            if let Some(found_thread) = self.cpu.decoder_invalid.iter_mut().find(|t| &t.name == name) {
                found_thread.value.push(value)

            } else {
                self.cpu.decoder_invalid.push(CpuThread { name: name.to_string(), value: vec![value] })
            }
        }
        Some(())
    }

    pub fn get_flows(&mut self, json: BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
        let stream = Deserializer::from_reader(json).into_iter::<Value>();
        let mut proto_str: String;
        let mut protocol: String;

        for value in stream {
            match value {
                Ok(value) => {
                    let trasport_proto =  value.get("proto");
                    let app_proto = value.get("app_proto");

                    if app_proto.is_none() || app_proto.and_then(|p| p.as_str()).ok_or("Cannot parse protocol.")? == "failed"  {
                        proto_str = trasport_proto
                            .and_then(|p| p.as_str())
                            .ok_or("Cannot parse protocol.")?
                            .to_lowercase();

                        protocol = TrasportProtocols::from_str(proto_str.as_str())
                            .map(|p| format!("{:?}", p))
                            .unwrap_or("".to_string());

                        if protocol.is_empty() {
                            continue;
                        }
                    }
                    else {
                        proto_str = app_proto
                            .and_then(|p| p.as_str())
                            .ok_or("Cannot parse protocol.")?
                            .to_lowercase();

                        protocol = AppLayerProtocols::from_str(proto_str.as_str())
                            .map(|p| format!("{:?}", p))
                            .unwrap_or("".to_string());

                        if protocol.is_empty() {
                            continue;
                        }
                    }
                    let flow_id = value.get("flow_id").and_then(|f| f.as_u64()).ok_or("Cannot find flow id.")?;
                    let flow = value.get("flow").ok_or("Cannot find flow object.")?;
                    let age = flow.get("age").and_then(|f| f.as_u64()).ok_or("Cannot find a flow duration.")?;
                    let packets = flow.get("pkts_toserver").and_then(|f| f.as_u64()).ok_or("Cannot find packets to server.")? +
                        value.get("flow").and_then(|a| a.get("pkts_toclient")).and_then(|f| f.as_u64()).ok_or("Cannot find packets to client.")?;
                    let bytes_to_client = flow.get("bytes_toclient").and_then(|f| f.as_u64()).ok_or("Cannot find bytes to client.")?;
                    let bytes_to_server = flow.get("bytes_toserver").and_then(|f| f.as_u64()).ok_or("Cannot find packets bytes to server.")?;
                    let start = flow.get("start").ok_or("Cannot find start flow value").and_then(|s| self.find_flow_start_end_time(s, true))?;
                    let end = flow.get("end").ok_or("Cannot find end flow value").and_then(|e| self.find_flow_start_end_time(e, false))?;
                    let state = flow.get("state").and_then(|f| f.as_str()).ok_or("Cannot find a flow state.")?.to_string();
                    let reason = flow.get("reason").and_then(|f| f.as_str()).ok_or("Cannot find a flow reason.")?.to_string();
                    let proto = value.get("proto").and_then(|f| f.as_str()).ok_or("Cannot find a flow protocol.")?.to_string();

                    let flow = Flow  {
                        flow_id,
                        age,
                        packets,
                        bytes_to_client,
                        bytes_to_server,
                        start,
                        end,
                        state,
                        reason,
                        proto
                    };

                    if let Some(flows) = self.flow.flows.get_mut(protocol.as_str()) {
                        flows.push(flow);
                    } else {
                        self.flow.flows.insert(protocol, vec![flow]);
                    }
                },
                Err(_) =>
                    return Err(Box::from("Unable to parse flows.json."))
            }
        }
        Ok(())
    }

    pub fn find_flow_start_end_time(&self, time: &Value, start: bool) -> Result<u64, &'static str> {
        let time_str = time.as_str().ok_or("Time is not a string.")?;

        let date_time: DateTime<FixedOffset> = time_str.parse().map_err(|_| "Invalid timestamp")?;

        Ok(date_time.timestamp() as u64)
    }
}