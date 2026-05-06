use pcap::{Capture, Device};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

struct FlowRecord {
    spkts: u32,
    syn: u32,
}

fn main() {
    let interface = std::env::var("INTERFACE").unwrap_or_else(|_| "eth0".to_string());
    let token = std::env::var("INFLUX_TOKEN").expect("INFLUX_TOKEN not set");
    
    let flow_table = Arc::new(Mutex::new(HashMap::<FlowKey, FlowRecord>::new()));
    let flow_table_clone = Arc::clone(&flow_table);

    // Поток экспорта данных в InfluxDB
    thread::spawn(move || {
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("{}/api/v2/write?org={}&bucket={}&precision=ns", 
            std::env::var("INFLUX_URL").unwrap(), 
            std::env::var("INFLUX_ORG").unwrap(), 
            std::env::var("INFLUX_BUCKET").unwrap()
        );

        loop {
            thread::sleep(FLUSH_INTERVAL);
            let mut payload = String::new();
            let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();

            {
                let mut table = flow_table_clone.lock().unwrap();
                if table.is_empty() { continue; }
                for (key, rec) in table.drain() {
                    payload.push_str(&format!(
                        "network_flow,src_ip={},dst_ip={} spkts={}i,syn={}i {}\n",
                        key.src_ip, key.dst_ip, rec.spkts, rec.syn, now_ns
                    ));
                }
            }

            if !payload.is_empty() {
                let _ = agent.post(&url)
                    .set("Authorization", &format!("Token {}", token))
                    .set("Content-Type", "text/plain")
                    .send_string(&payload);
            }
        }
    });

    let device = Device::list().unwrap().into_iter()
        .find(|d| d.name == interface)
        .expect("Interface not found");
        
    let mut cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .snaplen(65535)
        .open().unwrap();

    println!("[*] ids Collector active on {}", interface);

    while let Ok(packet) = cap.next_packet() {
        if let Ok(value) = SlicedPacket::from_ethernet(packet.data) {
            if let Some(ip) = value.ip {
                let (src, dst) = match ip {
                    InternetSlice::Ipv4(h, _) => (IpAddr::V4(h.source_addr()), IpAddr::V4(h.destination_addr())),
                    InternetSlice::Ipv6(h, _) => (IpAddr::V6(h.source_addr()), IpAddr::V6(h.destination_addr())),
                };

                let mut is_syn = 0;
                if let Some(TransportSlice::Tcp(tcp)) = value.transport {
                    if tcp.syn() { is_syn = 1; }
                }

                let mut table = flow_table.lock().unwrap();
                let record = table.entry(FlowKey { src_ip: src, dst_ip: dst }).or_insert(FlowRecord { spkts: 0, syn: 0 });
                record.spkts += 1;
                record.syn += is_syn;
            }
        }
    }
}