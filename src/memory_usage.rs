use byte_unit::{Byte, UnitType};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use crate::structures::{Analysis, Answer, Change, Keys, Flow, MemcapChange};
use crate::module::Module;
use crate::{ACTIVE_LIMIT, HOST_HASHROW, IPPAIR_HASHROW, HOST_OBJECT, IPPAIR_OBJECT, MULTIPLIER, DEFRAG_TRACKER, DEFRAG_TRACKER_HASHROW, TCP_SESSION, TCP_STATE_QUEUE,
            STREAM_TCP_SACK_RECORD, FRAGMENTS, TCP_SEGMENT, MTU, MAX_PENDING_PACKETS, DEFAULT_PACKET_SIZE};

#[derive(Debug)]
pub struct MemoryModule {
    pub questions: HashMap<Keys, Value>, // changed
    pub flow_map: BTreeMap<u64, Flow>,
    pub debug: bool
}

impl Module for MemoryModule {
    fn new(analysis: &Analysis, debug: bool) -> Self {
        let keys = [
            Keys::max_memory_usage,
            Keys::memcap_pressure,
            Keys::memcap_pressure_max,
            Keys::avg_pkt_size,
            Keys::max_pkt_size,
            Keys::default_packet_size,
            Keys::flow_set,
            Keys::flow_memcap,
            Keys:: threads_stat,
            Keys::ippair_memcap,
            Keys::ippair_hashsize,
            Keys::ippair_prealloc,
            Keys::ippair_memuse,
            Keys::ippair_active,
            Keys::host_memcap,
            Keys::host_hashsize,
            Keys::host_prealloc,
            Keys::host_memuse,
            Keys::host_active,
            Keys::tcp_active_sessions,
            Keys::tcp_ssn_memcap_drop,
            Keys::tcp_pkt_on_wrong_thread,
            Keys::tcp_segment_memcap_drop,
            Keys::tcp_reassembly_gap,
            Keys::defrag_tracker_active,
            Keys::defrag_max_fragments, // from stats
            Keys::defrag_hashsize,
            Keys::defrag_trackers,
            Keys::defrag_max_frags,
            Keys::defrag_prealloc,
            Keys::defrag_memcap,
            Keys::max_pending_packets,
            Keys::stream_prealloc,
            Keys::stream_memcap,
            Keys::reassembly_memcap,
            Keys::reassembly_prealloc,
            Keys::tcp_active_segments,
            Keys::tcp_reassembly_memuse,
            Keys::defrag_max_frags_reached,
            Keys::defrag_max_trackers_reached,
            Keys::defrag_tracker_hard_reuse,

        ];

        let questions: HashMap<Keys, Value> =
            keys.into_iter()
                .map(|k| (k, Value::Null))
                .collect();

        Self { questions, flow_map: BTreeMap::new(), debug }

    }

    fn questions(&self) -> &HashMap<Keys, Value> {
        &self.questions
    }

    fn main(&mut self, answers: &Vec<Answer<'_>>)-> Vec<Change> {

        self.check_mem_warning_counter(answers);

        // IPPair and Host table
        *self.questions.get_mut(&Keys::ippair_hashsize).expect("Unable to get ippair_hashsize from intern table.") =
        Value::Number(self.get_ippair_host_defrag_hash_size(answers, &HashType::IPPair).into());

        *self.questions.get_mut(&Keys::ippair_prealloc).expect("Unable to get ippair_prealloc from intern table.") =
        Value::Number(self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::IPPair).into());

        *self.questions.get_mut(&Keys::host_hashsize).expect("Unable to get host_hashsize from intern table.") =
        Value::Number(self.get_ippair_host_defrag_hash_size(answers, &HashType::Host).into());

        *self.questions.get_mut(&Keys::host_prealloc).expect("Unable to get host_prealloc from intern table.") =
        Value::Number(self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Host).into());

        // Stream and Reassembly table
        *self.questions.get_mut(&Keys::stream_prealloc).expect("Unable to get host_prealloc from intern table.") =
        Value::Number(self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Stream).into());

        *self.questions.get_mut(&Keys::reassembly_prealloc).expect("Unable to get reassembly_prealloc from intern table.") =
        Value::Number(self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Reassembly).into());

        // Defrag table
        self.set_defrag_prealloc_trackers(answers);
        *self.questions.get_mut(&Keys::defrag_hashsize).expect("Unable to get defrag_hashsize from intern table.") =
        Value::Number(self.get_ippair_host_defrag_hash_size(answers, &HashType::Defrag).into());

        *self.questions.get_mut(&Keys::defrag_trackers).expect("Unable to get defrag_trackers from intern table.") =
        Value::Number(self.get_ippair_host_defrag_hash_size(answers, &HashType::Defrag).into());

        *self.questions.get_mut(&Keys::defrag_max_frags).expect("Unable to get defrag max fragments from intern table.") =
        Value::Number((self.get_ippair_host_defrag_hash_size(answers, &HashType::Defrag)*(self.get_max_fragments(answers) as u64)).into());

        let (max_pending_packets, default_packet_size) = self.get_packet_structures(answers);

        let changes : Vec<MemcapChange> = vec![
            MemcapChange {
            keys: Keys::ippair_memcap,
            value:self.get_ippair_memcap(answers) as u64
            },
            MemcapChange {
            keys: Keys::host_memcap,
            value: self.get_host_memcap(answers) as u64
            },
            MemcapChange {
                keys: Keys::defrag_memcap,
                value: self.get_defrag_memcap(answers) as u64
            },
            MemcapChange {
                keys: Keys::stream_memcap,
                value: self.get_stream_memcap(answers) as u64
            },
            MemcapChange {
                keys: Keys::reassembly_memcap,
                value: self.get_reassembly_memcap(answers) as u64
            },
            MemcapChange {
                keys: Keys::max_pending_packets,
                value: max_pending_packets
            },
            MemcapChange {
                keys: Keys::default_packet_size,
                value: default_packet_size
            }
        ];

        if self.free_memcap(answers, &changes, self.debug) {
            let ippair_memcap = changes.iter().find(|a| a.keys == Keys::ippair_memcap).expect("Unable to get ippair_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::ippair_memcap).expect("Unable to get ippair_memcap from intern table.") = Value::String(Byte::from_u64(ippair_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            let host_memcap = changes.iter().find(|a| a.keys == Keys::host_memcap).expect("Unable to get host_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::host_memcap).expect("Unable to get host_memcap from intern table.") = Value::String(Byte::from_u64(host_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            let defrag_memcap = changes.iter().find(|a| a.keys == Keys::defrag_memcap).expect("Unable to get defrag_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::defrag_memcap).expect("Unable to get defrag_memcap from intern table.") = Value::String(Byte::from_u64(defrag_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            let stream_memcap = changes.iter().find(|a| a.keys == Keys::stream_memcap).expect("Unable to get stream_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::stream_memcap).expect("Unable to get stream_memcap from intern table.") = Value::String(Byte::from_u64(stream_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            let reassembly_memcap = changes.iter().find(|a| a.keys == Keys::reassembly_memcap).expect("Unable to get reassembly_memcap from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::reassembly_memcap).expect("Unable to get reassembly_memcap from intern table.") = Value::String(Byte::from_u64(reassembly_memcap)
                .get_appropriate_unit(UnitType::Binary).to_string());

            let max_pending_packets = changes.iter().find(|a| a.keys == Keys::max_pending_packets).expect("Unable to get max_pending_packets from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::max_pending_packets).expect("Unable to get max_pending_packets from intern table.") =
            Value::Number(max_pending_packets.into());

            let default_packet_size = changes.iter().find(|a| a.keys == Keys::default_packet_size).expect("Unable to get default_packet_size from MemcapChange vector.").value;
            *self.questions.get_mut(&Keys::default_packet_size).expect("Unable to get default_packet_size from intern table.") =
                Value::Number(default_packet_size.into());

        }
        else {
            panic!("Unable to set memory_module memcaps (ippair, host, defrag, stream, reassembly), not enough memory. Memory check failed. Check max_memory_usage.")
        }

        Change::collect_changes(&self.questions)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SetTable {
    Set,
    Default
}

#[derive(Debug, Eq, PartialEq)]
pub enum HashType {
    IPPair,
    Host,
    Defrag,
    Stream,
    Reassembly
}

impl Default for SetTable {
    fn default() -> Self {
        SetTable::Default
    }
}

impl MemoryModule {

    fn check_mem_warning_counter(&self, answers: &Vec<Answer<'_>>) {

        let ippair_memcap_str = answers.iter().find(|a| a.key == &Keys::ippair_memcap).expect("Unable to get ippair memcap.").value.as_str().expect("Unable to get ippair memcap as str.");
        let ippair_memcap = Byte::parse_str(ippair_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert ippair_memcap to Bytes.");
        let ippair_memuse = answers.iter().find(|a| a.key == &Keys::ippair_memuse).expect("Unable to get ippair memuse maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get ippair memuse maximum.");
        if ippair_memuse == ippair_memcap {
            println!("IPpair memuse is 100%, continue.")
        }

        let host_memcap_str = answers.iter().find(|a| a.key == &Keys::ippair_memcap).expect("Unable to get host memcap.").value.as_str().expect("Unable to get hosy memcap as str.");
        let host_memcap = Byte::parse_str(host_memcap_str, true).ok().map(|b| b.as_u64()).expect("Unable to convert host_memcap to Bytes.");
        let host_memuse = answers.iter().find(|a| a.key == &Keys::host_memuse).expect("Unable to get host memuse maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get host memuse maximum.");
        if host_memuse == host_memcap {
            println!("Host memuse is 100%, continue.")
        }

        let defrag_max_frags_reached = answers.iter().find(|a| a.key == &Keys::defrag_max_frags_reached).expect("Unable to get max frags reached maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get max frags reached maximum.");
        if defrag_max_frags_reached > 0 {
            panic!("System doesn't have enough memory, reconfigure.")
        }

        let defrag_max_trackers_reached = answers.iter().find(|a| a.key == &Keys::defrag_max_trackers_reached).expect("Unable to get max trackers reached maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get  max trackers reached maximum.");
        let defrag_tracker_hard_reuse = answers.iter().find(|a| a.key == &Keys::defrag_tracker_hard_reuse).expect("Unable to get tracker hard reuse maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get tracker hard reuse maximum.");
        if defrag_max_trackers_reached > 0 ||  defrag_tracker_hard_reuse > 0 {
            panic!("Unable to set defragmentation memory, not enough memory, reconfigure.")
        }

        let tcp_ssn_memcap_drop = answers.iter().find(|a| a.key == &Keys::tcp_ssn_memcap_drop).expect("Unable to get ssn memcap drop maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get ssn memcap drop maximum.");
        if tcp_ssn_memcap_drop > 0 {
            panic!("Unable to set stream memory, not enough memory, reconfigure.")
        }

        let tcp_segment_memcap_drop = answers.iter().find(|a| a.key == &Keys::tcp_segment_memcap_drop).expect("Unable to get segment memcap drop maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get segment memcap drop maximum.");
        if tcp_segment_memcap_drop > 0 {
            panic!("Unable to set reassembly memory, not enough memory, reconfigure.")
        }

        let tcp_reassembly_gap = answers.iter().find(|a| a.key == &Keys::tcp_reassembly_gap).expect("Unable to get reassembly gap maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get reassembly gap maximum.");
        if tcp_reassembly_gap > 0 {
            println!("TCP traffic has gaps, continue.")
        }
    }

    fn get_max_ippair_active_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::ippair_active).expect("Unable to get ippair active maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get ippair active maximum.")
    }

    fn get_max_host_active_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::host_active).expect("Unable to get host active maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get host active maximum.")
    }

    fn get_max_tcp_active_sessions_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::tcp_active_sessions).expect("Unable to get tcp active sessions maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get tcp active sessions maximum.")
    }

    fn get_max_tcp_active_segments_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::tcp_active_segments).expect("Unable to get tcp active segments maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get tcp tcp active segments maximum.")
    }

    fn get_max_defrag_tracker_active_stat(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::defrag_tracker_active).expect("Unable to get defragtracker active maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get defragtracker active maximum.")
    }

    fn get_max_defrag_fragments_stat(&self, answers: &Vec<Answer<'_>>) -> f64 {
         answers.iter().find(|a| a.key == &Keys::defrag_max_fragments).expect("Unable to get defrag fragments maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_f64()).last()).expect("Unable to get defrag fragments maximum.")
    }

    fn get_max_fragments(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_defrag_fragments =  self.get_max_defrag_fragments_stat(answers);
        if max_defrag_fragments > FRAGMENTS {
            max_defrag_fragments
        } else {
            FRAGMENTS
        }
    }

    fn get_set_table(&self, answers: &Vec<Answer<'_>>, hash_type: &HashType) -> SetTable {
        let objects_active = match hash_type {
            HashType::Host => {
                self.get_max_host_active_stat(answers)
            },
            HashType::IPPair => {
                self.get_max_ippair_active_stat(answers)
            },
            HashType::Defrag => {
                self.get_max_defrag_tracker_active_stat(answers)
            },
            HashType::Stream => {
                self.get_max_tcp_active_sessions_stat(answers)
            },
            HashType::Reassembly => {
                self.get_max_tcp_active_segments_stat(answers)
            }
        };

        if objects_active > ACTIVE_LIMIT {
            SetTable::Set
        }else {
            SetTable::Default
        }
    }

    fn get_segment_max_overhead(&self, answers: &Vec<Answer<'_>>) -> u64 {
        let mut max_packet_overhead = 0;

        let reassembly_prealloc = answers.iter().find(|a| a.key == &Keys::reassembly_prealloc).expect("Unable to get reassembly prealloc.").value.as_u64().expect("Unable to get default packet size as u64.");

        let tcp_active_segments_vec: Vec<u64> = answers.iter().find(|a| a.key == &Keys::tcp_active_segments).expect("Unable to get tcp active segments maximum.").value.as_array().expect("Unable to get as tcp active segments array.")
            .iter().map(|v| v.as_u64().expect("Value is not a u64")).collect();

        let reassembly_memuse_vec: Vec<u64> = answers.iter().find(|a| a.key == &Keys::tcp_reassembly_memuse).expect("Unable to get reassembly memuse maximum.").value.as_array().expect("UNable to get reassembly memuse as array.")
            .iter().map(|v| v.as_u64().expect("Value is not a u64")).collect();

        for (active_segments, reassembly_memuse) in tcp_active_segments_vec.iter().zip(reassembly_memuse_vec.iter()) {
            if self.debug {
                println!("active_segments: {active_segments}, reassembly_memuse: {reassembly_memuse}");
                println!("reassembly_prealloc:{}", reassembly_prealloc*(self.get_workers(answers)as u64))
            }
            let overhead = reassembly_memuse - ((reassembly_prealloc * self.get_workers(answers) as u64) + active_segments)*(TCP_SEGMENT as u64);
            if self.get_max_tcp_active_sessions_stat(answers) == 0 {
                continue;
            }
            let packet_overhead = overhead/self.get_max_tcp_active_sessions_stat(answers);
            if packet_overhead > max_packet_overhead {
                max_packet_overhead= packet_overhead;
            }
        }

        if self.debug {
            println!("raw: max_packet_overhead: {max_packet_overhead}")
        }

        if max_packet_overhead == 0 {
            max_packet_overhead = MTU;
        }
        max_packet_overhead
    }

    fn get_ippair_memcap(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_ippair_active = if SetTable::Default == self.get_set_table(answers, &HashType::IPPair) {
            ACTIVE_LIMIT as f64
        } else {
            self.get_max_ippair_active_stat(answers) as f64
        };
        let hash_size = self.questions.get(&Keys::ippair_hashsize).expect("Unable to get ippair hash_size.").as_f64().expect("Unable to get ippair hash_size as f64.");
        let prealloc = self.questions.get(&Keys::ippair_prealloc).expect("Unable to get ippair hash_size.").as_f64().expect("Unable to get ippair hash_size as f64.");

        hash_size*IPPAIR_HASHROW+(max_ippair_active+prealloc*MULTIPLIER)*IPPAIR_OBJECT
    }

    fn get_host_memcap(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_host_active = if SetTable::Default == self.get_set_table(answers, &HashType::Host) {
            ACTIVE_LIMIT as f64
        } else {
            self.get_max_host_active_stat(answers) as f64
        };
        let hash_size = self.questions.get(&Keys::host_hashsize).expect("Unable to get host hash_size.").as_f64().expect("Unable to get host hash_size as f64.");
        let prealloc = self.questions.get(&Keys::host_prealloc).expect("Unable to get host hash_size.").as_f64().expect("Unable to get host hash_size as f64.");

        hash_size*HOST_HASHROW+(max_host_active+prealloc*MULTIPLIER)*HOST_OBJECT
    }

    fn get_ippair_host_defrag_stream_reassembly_prealloc(&self, answers: &Vec<Answer<'_>>, hash_type: &HashType) -> u64 {
        let set_table = self.get_set_table(answers, hash_type);
        match set_table {
            SetTable::Set => {
                match hash_type {
                    HashType::Host => {
                        self.get_max_host_active_stat(answers)/2
                    },
                    HashType::IPPair => {
                        self.get_max_ippair_active_stat(answers)/2
                    },
                    HashType::Defrag => {
                        self.get_max_defrag_tracker_active_stat(answers)/2
                    },
                    HashType::Stream => {
                        (self.get_max_tcp_active_sessions_stat(answers)/2)/(self.get_workers(answers) as u64)
                    },
                    HashType::Reassembly => {
                        (self.get_max_tcp_active_segments_stat(answers)/2)/(self.get_workers(answers) as u64)

                    }
                }
            },
            SetTable::Default => {
                if *hash_type == HashType::Stream || *hash_type  == HashType::Reassembly {
                    (ACTIVE_LIMIT/2)/self.get_workers(answers) as u64
                }else {
                    ACTIVE_LIMIT/2
                }
            }
        }
    }

    fn get_ippair_host_defrag_hash_size(&self, answers: &Vec<Answer<'_>>, hash_type: &HashType) -> u64 {
        let set_table = self.get_set_table(answers, hash_type);
        match set_table {
            SetTable::Set => {
                match hash_type {
                    HashType::Host => {
                        self.get_max_host_active_stat(answers).next_power_of_two()
                    },
                    HashType::IPPair => {
                        self.get_max_ippair_active_stat(answers).next_power_of_two()
                    },
                    HashType::Defrag => {
                        self.get_max_defrag_tracker_active_stat(answers).next_power_of_two()
                    },
                    _ =>  {
                        panic!("HashType {:?} not defined for hashsize.", set_table)
                    }
                }
            },
            SetTable::Default => {
                ACTIVE_LIMIT
            }
        }
    }

    fn set_defrag_prealloc_trackers(&mut self, answers: &Vec<Answer<'_>>) {
        let prealloc = answers.iter().find(|a| a.key == &Keys::defrag_prealloc).expect("Unable to get defrag prealloc.").value.as_str().expect("Unable to get defrag prealloc.");
        if prealloc == "yes" {
            *self.questions.get_mut(&Keys::defrag_prealloc).expect("Unable to get defrag_prealloc from intern table.") =
                Value::String(prealloc.to_string());
        }
    }

    fn get_defrag_memcap(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_defrag_tracker_active = if SetTable::Default == self.get_set_table(answers, &HashType::Defrag) {
            ACTIVE_LIMIT as f64
        } else {
            self.get_max_defrag_tracker_active_stat(answers) as f64
        };
        let hashsize  = self.questions.get(&Keys::defrag_hashsize).expect("Unable to get defrag.").as_f64().expect("Unable to get defrag hash_size as f64.");

        hashsize*DEFRAG_TRACKER_HASHROW+(max_defrag_tracker_active+(self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Defrag) as f64)*MULTIPLIER)*DEFRAG_TRACKER
    }

    fn get_stream_memcap(&self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_tcp_active_sessions = if SetTable::Default == self.get_set_table(answers, &HashType::Stream) {
          ACTIVE_LIMIT as f64
        } else {
            self.get_max_tcp_active_sessions_stat(answers) as f64
        };

        if self.debug {
            println!("max_tcp_active_sessions: {max_tcp_active_sessions}");
        }

        let prealloc = self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Stream) as f64;

        (max_tcp_active_sessions+(prealloc*self.get_workers(answers)))*(TCP_SESSION+TCP_STATE_QUEUE+STREAM_TCP_SACK_RECORD)
    }

    fn get_reassembly_memcap(&mut self, answers: &Vec<Answer<'_>>) -> f64 {
        let max_tcp_active_segments = if SetTable::Default == self.get_set_table(answers, &HashType::Reassembly) {
            ACTIVE_LIMIT as f64
        } else {
            self.get_max_tcp_active_segments_stat(answers) as f64
        };

        let max_tcp_active_sessions = if SetTable::Default == self.get_set_table(answers, &HashType::Stream) {
            ACTIVE_LIMIT as f64
        } else {
            self.get_max_tcp_active_sessions_stat(answers) as f64
        };

        let max_segment_overhead = self.get_segment_max_overhead(answers) as f64;
        let prealloc = self.get_ippair_host_defrag_stream_reassembly_prealloc(answers, &HashType::Reassembly) as f64;
        let workers = self.get_workers(answers);

        if self.debug {
            println!("max_packet_overhead: {max_segment_overhead}, max_tcp_active_segments: {max_tcp_active_segments}");
            println!("max_tcp_active_sessions:{max_tcp_active_sessions}, prealloc:{prealloc}")
        }

        (max_tcp_active_sessions+(prealloc*workers))*max_segment_overhead+(max_tcp_active_segments+(prealloc*workers))*(TCP_SEGMENT as f64)
    }

    fn get_max_packet_size(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::max_pkt_size).expect("Unable to get tcp packet size maximum.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).max()).expect("Unable to get packet size maximum.")
    }

    fn get_avg_packet_size(&self, answers: &Vec<Answer<'_>>) -> u64 {
        answers.iter().find(|a| a.key == &Keys::avg_pkt_size).expect("Unable to get packet size average.").value.as_array().and_then(|arr| arr.iter().filter_map(|v| v.as_u64()).last()).expect("Unable to get packet size average.")
    }

    fn get_packet_structures(&self, answers: &Vec<Answer<'_>>) -> (u64, u64) { // (max_pending_packets, default_packet_size)
        let max_pending_packets: u64 = match MAX_PENDING_PACKETS {
            MaxPendingPackets::ten_thousand => {
                10000
            }
            MaxPendingPackets::fifteen_thousand => {
                15000
            }
            MaxPendingPackets::twenty_thousand => {
                20000
            }
            MaxPendingPackets::twenty_five_thousand => {
                25000
            }
            MaxPendingPackets::thirty_thousand => {
                30000
            }
            MaxPendingPackets::thirty_five_thousand => {
                35000
            }
            MaxPendingPackets::forthy_thousand => {
                40000
            }
            MaxPendingPackets::forthy_five_thousand => {
                45000
            }
            MaxPendingPackets::fifthy_thousand => {
                50000
            }
            MaxPendingPackets::fifthy_five_thousand => {
                55000
            }
            MaxPendingPackets::sixty_thousand => {
                60000
            }
            MaxPendingPackets::sixty_five_thousand => {
                65000
            }
        };

        let default_packet_size = match  DEFAULT_PACKET_SIZE {
            DefaultPacketSize::Zero => {0},
            DefaultPacketSize::Average => {self.get_avg_packet_size(answers)},
            DefaultPacketSize::Max => {self.get_max_packet_size(answers)}
        };

        if self.debug  {
            println!("max_pending_packets: {max_pending_packets}, default_packet_size: {default_packet_size}");
        }

        (max_pending_packets, default_packet_size)
    }
}

pub enum MaxPendingPackets {
    ten_thousand,
    fifteen_thousand,
    twenty_thousand,
    twenty_five_thousand,
    thirty_thousand,
    thirty_five_thousand,
    forthy_thousand,
    forthy_five_thousand,
    fifthy_thousand,
    fifthy_five_thousand,
    sixty_thousand,
    sixty_five_thousand
}

pub enum DefaultPacketSize {
    Zero,
    Average,
    Max
}