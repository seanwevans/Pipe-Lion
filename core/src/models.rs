//! Shared, serializable packet model types produced by the parsers.

use serde::Serialize;

#[derive(Serialize)]
pub struct Packet {
    pub layers: Option<DecodedLayers>,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    /// Human-readable Info text for this packet, e.g.
    /// `DNS 10.0.0.5:51234 -> 1.1.1.1:53 Standard query 0x1a2b A example.com`.
    pub info: String,
    pub hex_preview: String,
    pub ascii_preview: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Clone)]
pub struct EthernetHeader {
    pub source_mac: String,
    pub destination_mac: String,
    pub ethertype: u16,
}
#[derive(Serialize, Clone)]
pub struct Ipv4Header {
    pub source: String,
    pub destination: String,
    pub protocol: u8,
    pub header_length: usize,
    pub total_length: usize,
    pub ttl: u8,
}
#[derive(Serialize, Clone)]
pub struct Ipv6Header {
    pub source: String,
    pub destination: String,
    pub next_header: u8,
    pub payload_length: usize,
    pub hop_limit: u8,
}
#[derive(Serialize, Clone)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    /// Data offset in bytes; where the application payload starts.
    pub header_length: usize,
}
#[derive(Serialize, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
}
#[derive(Serialize, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub description: String,
    pub version: String,
}

#[derive(Serialize, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
    pub qclass: String,
}

#[derive(Serialize, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub truncated: bool,
    pub opcode: String,
    pub rcode: String,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub questions: Vec<DnsQuestion>,
}

#[derive(Serialize, Clone)]
pub struct TlsClientHello {
    pub version: String,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct TlsRecord {
    pub content_type: String,
    pub version: String,
    pub handshake_type: Option<String>,
    pub client_hello: Option<TlsClientHello>,
}

#[derive(Serialize, Clone, Default)]
pub struct DecodedLayers {
    pub ethernet: Option<EthernetHeader>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub icmp: Option<IcmpHeader>,
    pub dns: Option<DnsHeader>,
    pub tls: Option<TlsRecord>,
}

#[derive(Serialize)]
pub struct PacketProcessingResult {
    pub packets: Vec<Packet>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

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
