use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use serde_json::{to_string, Deserializer, Value};
use std::collections::HashMap;
use serde::Serialize;
use std::os::linux::raw::stat;
use crate::json;
use crate::structures::{Protocols, AppLayerProtocols, TrasportProtocols, CreatedLogs};

pub fn open_json(file: &PathBuf) -> Result<BufReader<File>, Box<dyn std::error::Error>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);
    Ok(reader)
}

pub fn get_the_last_one_stats(json: BufReader<File>) -> Result<Value, Box<dyn std::error::Error>> {
    let stream = Deserializer::from_reader(json).into_iter::<Value>();
    let last = stream.last().ok_or("Empty stream")??;
    Ok(last)
}

pub fn get_flows(json: BufReader<File>, protocols_flows: &mut HashMap<String, Vec<Flow>>) -> Result<(), Box<dyn std::error::Error>> {
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

                let time = value.get("flow").and_then(|a| a.get("age")).and_then(|f| f.as_f64()).ok_or("Cannot find a flow duration.")?;
                let packets = value.get("flow").and_then(|a| a.get("pkts_toserver")).and_then(|f| f.as_u64()).ok_or("Cannot find packets to server.")? +
                    value.get("flow").and_then(|a| a.get("pkts_toclient")).and_then(|f| f.as_u64()).ok_or("Cannot find packets to client.")?;

                let flow = Flow  {
                    time,
                    packets
                };

                if let Some(flows) = protocols_flows.get_mut(protocol.as_str()) {
                    flows.push(flow);
                } else {
                    protocols_flows.insert(protocol, vec![flow]);
                }
            },
            Err(_) =>
            return Err(Box::from("Unable to parse flows.json."))
        }
    }
    Ok(())
}

pub fn save_to_json(json: &Value, file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(file)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &json)?;
    Ok(())
}

#[derive(Serialize, Debug)]
pub struct Preconfiguration {
    protocol_flows: HashMap<String, Vec<Flow>>,
    uptime: f64,
}

#[derive(Serialize, Debug)]
pub struct Flow {
    time: f64,
    packets: u64
}

impl Preconfiguration {
    pub fn new() -> Self {
        Self {
            protocol_flows: HashMap::new(),
            uptime: 0.0,
        }
    }

    pub fn create_preconfiguration_structure_and_save(&mut self, logs: &CreatedLogs) -> Result<(), Box<dyn std::error::Error>> {
        let stats =  match json::open_json(&logs.stats) {
            Ok(stats) => {stats},
            Err(e) => { return Err(e);}
        };

        let stats  = match json::get_the_last_one_stats(stats){
            Ok(stats) => {stats},
            Err(e) => {return Err(e);}

        };

        if let None = self.find_uptime(&stats) {
            let err: Box<dyn std::error::Error> = "Uptime cannot be parsed.".into();
            return  Err(err);
        }

        let flows = match json::open_json(&logs.flows) {
            Ok(flows) => {flows},
            Err(e) => { return Err(e);}
        };

        if let Err(e) = get_flows(flows, &mut self.protocol_flows) {
            return Err(e);
        }

        println!("{:?}", self.protocol_flows);

        let flows_in_value = serde_json::to_value(&self.protocol_flows)?;
        if let Err(e) = save_to_json(&flows_in_value, &logs.preconfiguration) {
            return Err(e);
        }

        Ok(())
    }

    // pub fn find_protocol_flows(&mut self, stats: &Value) -> Option<()>  {
    //     let tcp = stats
    //     .get("stats")
    //     .and_then(|s| s.get("flow"))
    //     .and_then(|d| d.get("tcp"))
    //     .and_then(|u| u.as_u64());
    //
    //     if let Some(tcp) = tcp {
    //         self.protocol_flows.insert(format!("{:?}", Protocols::Transport(TrasportProtocols::TCP)), Vec::new());
    //     }
    //
    //     let udp = stats
    //         .get("stats")
    //         .and_then(|s| s.get("flow"))
    //         .and_then(|d| d.get("udp"))
    //         .and_then(|u| u.as_u64());
    //
    //     if let Some(udp) = udp {
    //         self.protocol_flows.insert(format!("{:?}", Protocols::Transport(TrasportProtocols::UDP)), Vec::new());
    //     }
    //
    //     let app_layer_flows = stats
    //     .get("stats")
    //     .and_then(|s|s.get("app_layer"))
    //     .and_then(|a| a.get("flow"))
    //     .and_then(|f| f.as_object())?;
    //
    //     for (key, value) in app_layer_flows {
    //         if let Some(protocol) = AppLayerProtocols::from_str(key) {
    //             if let Some(flow_count) = value.as_u64() {
    //                     self.protocol_flows.insert(format!("{:?}", Protocols::AppLayer(protocol)), Vec::new());
    //             }
    //         }
    //     }
    //     Some(())
    // }
    //
    pub fn find_uptime(&mut self, stats: &Value) -> Option<()> {
        self.uptime = stats
        .get("stats")
        .and_then(|s| s.get("uptime"))
        .and_then(|u| u.as_f64())?;
        Some(())
    }

    // pub fn find_flows(&mut self, stats: &Value) -> Option<u64> {
    //     stats
    //     .get("stats")
    //     .and_then(|s| s.get("flow"))
    //     .and_then(|f| f.get("total"))
    //     .and_then(|t| t.as_u64())
    // }

    /*pub fn find_throughput_bytes(&mut self, stats: &Value) -> Option<()> {
        self.throughput_bytes = stats
        .get("stats")
        .and_then(|s| s
        .get("decoder") )
        .and_then(|d| d.get("bytes"))
        .and_then(|b| b.as_f64())?;
        Some(())
    }

    pub fn find_throughput_pkts(&mut self, stats: &Value) -> Option<()> {
        self.throughput_pkts = stats
        .get("stats")
        .and_then(|s| s
        .get("decoder") )
        .and_then(|d| d.get("pkts"))
        .and_then(|p| p.as_f64())?;
        Some(())
    }*/
}








