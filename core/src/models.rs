use serde::Serialize;

#[derive(Serialize)]
pub struct PacketSummary {
    pub info: String,
    pub summary: String,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: usize,
    pub hex_preview: String,
    pub ascii_preview: String,
}

#[derive(Serialize)]
pub struct Packet {
    pub layers: Option<DecodedLayers>,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Clone)]
pub struct EthernetHeader { pub source_mac: String, pub destination_mac: String, pub ethertype: u16 }
#[derive(Serialize, Clone)]
pub struct Ipv4Header { pub source: String, pub destination: String, pub protocol: u8, pub header_length: usize, pub total_length: usize, pub ttl: u8 }
#[derive(Serialize, Clone)]
pub struct Ipv6Header { pub source: String, pub destination: String, pub next_header: u8, pub payload_length: usize, pub hop_limit: u8 }
#[derive(Serialize, Clone)]
pub struct TcpHeader { pub source_port: u16, pub destination_port: u16 }
#[derive(Serialize, Clone)]
pub struct UdpHeader { pub source_port: u16, pub destination_port: u16, pub length: u16 }
#[derive(Serialize, Clone)]
pub struct IcmpHeader { pub icmp_type: u8, pub icmp_code: u8, pub description: String, pub version: String }

#[derive(Serialize, Clone, Default)]
pub struct DecodedLayers {
    pub ethernet: Option<EthernetHeader>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub icmp: Option<IcmpHeader>,
}

#[derive(Serialize)]
pub struct PacketProcessingResult { pub packets: Vec<Packet>, pub warnings: Vec<String>, pub errors: Vec<String> }

pub struct PacketMetadata {
    pub layers: Option<DecodedLayers>,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub summary: String,
    pub length: usize,
}

#[derive(Default)]
pub struct PacketAnalysis {
    pub source: String,
    pub layers: DecodedLayers,
    pub destination: String,
    pub protocol: String,
    pub summary: String,
}
