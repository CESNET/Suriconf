use serde_json::Value;
use std::collections::{HashMap};
use crate::structures::{Analysis, Answer, Change, Keys};
use crate::module::Module;

#[derive(Debug)]
pub struct MemoryModule {
    pub questions: HashMap<Keys, Value>, // changed
}

impl Module for MemoryModule {
    fn new(analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::max_memory_usage,
            Keys::memcap_pressure,
            Keys::memcap_pressure_max,
            Keys::avg_pkt_size,
            Keys::max_pkt_size,
            Keys::flow_set,
            // Keys::tcp_active_sessions,
            // Keys::tcp_ssn_memcap_drop,
            // Keys::tcp_pkt_on_wrong_thread,
            // Keys::tcp_segment_memcap_drop,
            // Keys::tcp_stream_depth_reached,
            // Keys::tcp_reaassembly_gap,
            // Keys::tcp_memuse,
            // Keys::tcp_reassembly_memuse,
            // Keys::
        ];

        let questions: HashMap<Keys, Value> =
            keys.into_iter()
                .map(|k| (k, Value::Null))
                .collect();

        Self { questions }

    }

    fn questions(&self) -> &HashMap<Keys, Value> {
        &self.questions
    }

    fn main(&mut self, answers: &Vec<Answer<'_>>)-> Vec<Change> {
        todo!()
    }
}

impl MemoryModule {

    fn get_defrag_hashsize(&self) {

    }
    fn get_prealloc_trackers(&self) {}

    fn get_max_fragments(&self) {

    }

    fn get_defrag_memcap(&self) {
        // TODO  pozor na pamet pro fragmenty a pakety
    }

    fn get_ippair_memcap(&self) {

    }

    fn get_host_memcap(&self) {

    }

    fn get_stream_memcap(&self) {

    }

    fn get_reassembly_memcap(&self) {

    }

    fn get_max_pending_packets(&self) {
        // workers*max-pending-packets * (default-packet-size + sizeof(Packet_))
        // tady zkouset jak to bude ovlivnovat ??
        // 10 000 - 65000
        // nax pending packets nema mit vliv
        // dps na 0
        // flow_moudule -> musi bezet minimalne 360 s
        // jestli je end_start a end_timeout v sekundach a kdyztak prodluz dobu cekani 
    }

    fn get_avg_packet_size(&self) {

    }

    fn get_default_packet_size(&self) {

    }

    // fn get_default_packet_size_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
    //     // TODO answers.iter().find(|a| a.key == &Keys::flow_prealloc).expect("Unable to get prealloc.").value.as_u64().expect("Unable to get prealloc as u64.")
    // }

}