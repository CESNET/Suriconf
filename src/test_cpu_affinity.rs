struct TestCPUAffinity {
    max_cpus: u64,
    max_memory: f64,
    capture_mode: CaptureMode,
    
    //protocol_flows:
}
// create the structure and with help of Value send just names


enum CaptureMode {
    DPDK,
    AF_PACKET
}