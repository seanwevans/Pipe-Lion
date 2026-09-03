use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use wasm_bindgen::prelude::*;

mod core_format;
mod decode;
mod models;
mod pcap;
mod pcapng;
mod preview;

use crate::core_format::{CaptureFormat, detect_format};
use crate::decode::build_summary_from_layers;
use crate::models::{
    DecodedLayers, EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, Packet, PacketAnalysis,
    PacketMetadata, PacketProcessingResult, PacketSummary, TcpHeader, UdpHeader,
};
use crate::pcap::process_pcap;
use crate::pcapng::process_pcapng;
use crate::preview::{build_ascii_preview, build_hex_preview};

pub(crate) const EM_DASH: &str = "\u{2014}";
pub(crate) const ARROW: &str = "\u{2192}";

fn serialize_result(result: &PacketProcessingResult) -> String {
    serde_json::to_string(result)
        .unwrap_or_else(|_| "{\"packets\":[],\"warnings\":[],\"errors\":[]}".into())
}

pub(crate) fn format_timestamp(seconds: i64, fractional: u64, resolution: u64) -> String {
    if seconds < 0 {
        return "0.000000".to_string();
    }
    if let Some(digits) = decimal_digits(resolution) {
        format!("{seconds}.{fractional:0digits$}")
    } else {
        let total = seconds as f64 + fractional as f64 / resolution as f64;
        format!("{total:.6}")
    }
}

fn decimal_digits(resolution: u64) -> Option<usize> {
    if resolution == 0 {
        return None;
    }
    let mut value = resolution;
    let mut digits = 0usize;
    while value > 1 {
        if !value.is_multiple_of(10) {
            return None;
        }
        value /= 10;
        digits += 1;
    }
    Some(digits)
}

pub(crate) fn create_packet(meta: PacketMetadata, payload: &[u8]) -> Packet {
    let PacketMetadata {
        time,
        source,
        destination,
        protocol,
        summary,
        length,
        layers,
    } = meta;

    let hex_preview = build_hex_preview(payload, 32);
    let ascii_preview = build_ascii_preview(payload, 32);
    let summary_payload = PacketSummary {
        info: summary.clone(),
        summary: summary.clone(),
        time: time.clone(),
        src: source.clone(),
        dst: destination.clone(),
        protocol: protocol.clone(),
        length,
        hex_preview,
        ascii_preview,
    };
    let info = serde_json::to_string(&summary_payload).unwrap_or_else(|_| summary.clone());

    Packet {
        layers,
        time,
        source,
        destination,
        protocol,
        length,
        info,
        payload: payload.to_vec(),
    }
}

pub(crate) fn analyze_payload(linktype: u32, payload: &[u8]) -> PacketAnalysis {
    match linktype {
        1 => analyze_ethernet_frame(payload),
        0 => analyze_null_loopback(payload)
            .unwrap_or_else(|| fallback_analysis(linktype, payload.len())),
        101 | 228 => {
            parse_ipv4_packet(payload).unwrap_or_else(|| fallback_analysis(linktype, payload.len()))
        }
        229 => {
            parse_ipv6_packet(payload).unwrap_or_else(|| fallback_analysis(linktype, payload.len()))
        }
        _ => analyze_raw_ip(payload).unwrap_or_else(|| fallback_analysis(linktype, payload.len())),
    }
}

fn fallback_analysis(linktype: u32, length: usize) -> PacketAnalysis {
    PacketAnalysis {
        source: EM_DASH.to_string(),
        layers: DecodedLayers::default(),
        destination: EM_DASH.to_string(),
        protocol: format!("LINKTYPE {linktype}"),
        summary: format!("Captured {length} bytes (linktype {linktype})"),
    }
}

fn analyze_raw_ip(payload: &[u8]) -> Option<PacketAnalysis> {
    payload.first().and_then(|byte| match byte >> 4 {
        4 => parse_ipv4_packet(payload),
        6 => parse_ipv6_packet(payload),
        _ => None,
    })
}

fn analyze_null_loopback(payload: &[u8]) -> Option<PacketAnalysis> {
    if payload.len() < 4 {
        return None;
    }
    let family = u32::from_ne_bytes(payload[0..4].try_into().ok()?);
    let data = &payload[4..];
    match family {
        2 => parse_ipv4_packet(data),
        24 => parse_ipv6_packet(data),
        _ => None,
    }
}

fn analyze_ethernet_frame(frame: &[u8]) -> PacketAnalysis {
    if frame.len() < 14 {
        return fallback_analysis(1, frame.len());
    }
    let dst_mac = format_mac(&frame[0..6]);
    let src_mac = format_mac(&frame[6..12]);
    let ethertype = u16::from_be_bytes(frame[12..14].try_into().ok().unwrap_or([0, 0]));
    let ethernet = EthernetHeader {
        source_mac: src_mac.clone(),
        destination_mac: dst_mac.clone(),
        ethertype,
    };
    match ethertype {
        0x0800 => {
            if let Some(mut analysis) = parse_ipv4_packet(&frame[14..]) {
                if analysis.source == EM_DASH {
                    analysis.source = src_mac.clone();
                }
                if analysis.destination == EM_DASH {
                    analysis.destination = dst_mac.clone();
                }
                analysis.layers.ethernet = Some(ethernet.clone());
                return analysis;
            }
        }
        0x86DD => {
            if let Some(mut analysis) = parse_ipv6_packet(&frame[14..]) {
                if analysis.source == EM_DASH {
                    analysis.source = src_mac.clone();
                }
                if analysis.destination == EM_DASH {
                    analysis.destination = dst_mac.clone();
                }
                analysis.layers.ethernet = Some(ethernet.clone());
                return analysis;
            }
        }
        0x0806 => {
            if let Some(analysis) = parse_arp_packet(&frame[14..], &src_mac, &dst_mac) {
                return analysis;
            }
        }
        _ => {}
    }
    PacketAnalysis {
        source: src_mac,
        destination: dst_mac,
        protocol: format!("EtherType 0x{ethertype:04X}"),
        summary: format!(
            "Ethernet 0x{ethertype:04X} {ARROW} captured {} bytes",
            frame.len()
        ),
        layers: DecodedLayers {
            ethernet: Some(ethernet),
            ..DecodedLayers::default()
        },
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<PacketAnalysis> {
    if packet.len() < 20 {
        return None;
    }
    let version_ihl = packet[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_length = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    if total_length < ihl {
        return None;
    }
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    let payload_end = packet.len().min(total_length);
    let payload = if payload_end > ihl {
        &packet[ihl..payload_end]
    } else {
        &[]
    };

    let protocol_name = map_ip_protocol(protocol);
    let mut analysis = PacketAnalysis {
        source: src_ip.clone(),
        destination: dst_ip.clone(),
        protocol: protocol_name.to_string(),
        summary: format!("{protocol_name} {src_ip} {ARROW} {dst_ip}"),
        layers: DecodedLayers {
            ipv4: Some(Ipv4Header {
                source: src_ip.clone(),
                destination: dst_ip.clone(),
                protocol,
                header_length: ihl,
                total_length,
                ttl: packet[8],
            }),
            ..DecodedLayers::default()
        },
    };

    match protocol {
        6 | 17 | 132 => {
            if payload.len() >= 4 {
                let src_port = u16::from_be_bytes(payload[0..2].try_into().ok()?);
                let dst_port = u16::from_be_bytes(payload[2..4].try_into().ok()?);
                analysis.source = format_port(&src_ip, src_port);
                analysis.destination = format_port(&dst_ip, dst_port);
                if protocol == 6 {
                    analysis.layers.tcp = Some(TcpHeader {
                        source_port: src_port,
                        destination_port: dst_port,
                    });
                } else if protocol == 17 {
                    let udp_len = if payload.len() >= 6 {
                        u16::from_be_bytes(payload[4..6].try_into().ok().unwrap_or([0, 0]))
                    } else {
                        0
                    };
                    analysis.layers.udp = Some(UdpHeader {
                        source_port: src_port,
                        destination_port: dst_port,
                        length: udp_len,
                    });
                }
                analysis.summary = format!(
                    "{protocol_name} {} {ARROW} {}",
                    analysis.source, analysis.destination
                );
            }
        }
        1 => {
            if payload.len() >= 2 {
                let icmp_type = payload[0];
                let icmp_code = payload[1];
                let description = describe_icmpv4(icmp_type, icmp_code);
                analysis.layers.icmp = Some(IcmpHeader {
                    icmp_type,
                    icmp_code,
                    description: description.clone(),
                    version: "ICMP".to_string(),
                });
                analysis.summary = format!("ICMP {src_ip} {ARROW} {dst_ip} ({description})");
            }
        }
        _ => {}
    }

    analysis.summary = build_summary_from_layers(&analysis.layers, analysis.summary);
    Some(analysis)
}

fn parse_ipv6_packet(packet: &[u8]) -> Option<PacketAnalysis> {
    if packet.len() < 40 {
        return None;
    }
    if packet[0] >> 4 != 6 {
        return None;
    }
    let mut next_header = packet[6];
    let src_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
    let src_ip = Ipv6Addr::from(src_bytes).to_string();
    let dst_ip = Ipv6Addr::from(dst_bytes).to_string();
    let mut offset = 40usize;

    // Naively skip a few common extension headers.
    for _ in 0..4 {
        match next_header {
            0 | 43 | 60 => {
                if packet.len() < offset + 8 {
                    break;
                }
                let hdr_len = ((packet[offset + 1] as usize) + 1) * 8;
                if packet.len() < offset + hdr_len {
                    break;
                }
                next_header = packet[offset];
                offset += hdr_len;
            }
            44 => {
                if packet.len() < offset + 8 {
                    break;
                }
                next_header = packet[offset];
                offset += 8;
            }
            51 => {
                if packet.len() < offset + 4 {
                    break;
                }
                let hdr_len = ((packet[offset + 1] as usize) + 2) * 4;
                if packet.len() < offset + hdr_len {
                    break;
                }
                next_header = packet[offset];
                offset += hdr_len;
            }
            _ => break,
        }
    }

    if offset > packet.len() {
        return None;
    }
    let payload = &packet[offset..];
    let protocol_name = map_ip_protocol(next_header);
    let mut analysis = PacketAnalysis {
        source: src_ip.clone(),
        destination: dst_ip.clone(),
        protocol: protocol_name.to_string(),
        summary: format!("{protocol_name} {src_ip} {ARROW} {dst_ip}"),
        layers: DecodedLayers {
            ipv6: Some(Ipv6Header {
                source: src_ip.clone(),
                destination: dst_ip.clone(),
                next_header,
                payload_length: payload.len(),
                hop_limit: packet[7],
            }),
            ..DecodedLayers::default()
        },
    };

    match next_header {
        6 | 17 | 132 => {
            if payload.len() >= 4 {
                let src_port = u16::from_be_bytes(payload[0..2].try_into().ok()?);
                let dst_port = u16::from_be_bytes(payload[2..4].try_into().ok()?);
                analysis.source = format_port(&src_ip, src_port);
                analysis.destination = format_port(&dst_ip, dst_port);
                if next_header == 6 {
                    analysis.layers.tcp = Some(TcpHeader {
                        source_port: src_port,
                        destination_port: dst_port,
                    });
                } else if next_header == 17 {
                    let udp_len = if payload.len() >= 6 {
                        u16::from_be_bytes(payload[4..6].try_into().ok().unwrap_or([0, 0]))
                    } else {
                        0
                    };
                    analysis.layers.udp = Some(UdpHeader {
                        source_port: src_port,
                        destination_port: dst_port,
                        length: udp_len,
                    });
                }
                analysis.summary = format!(
                    "{protocol_name} {} {ARROW} {}",
                    analysis.source, analysis.destination
                );
            }
        }
        58 => {
            if payload.len() >= 2 {
                let icmp_type = payload[0];
                let icmp_code = payload[1];
                let description = describe_icmpv6(icmp_type, icmp_code);
                analysis.layers.icmp = Some(IcmpHeader {
                    icmp_type,
                    icmp_code,
                    description: description.clone(),
                    version: "ICMPv6".to_string(),
                });
                analysis.summary = format!("ICMPv6 {src_ip} {ARROW} {dst_ip} ({description})");
            }
        }
        _ => {}
    }

    analysis.summary = build_summary_from_layers(&analysis.layers, analysis.summary);
    Some(analysis)
}

fn parse_arp_packet(packet: &[u8], src_mac: &str, dst_mac: &str) -> Option<PacketAnalysis> {
    if packet.len() < 28 {
        return None;
    }
    let hw_type = u16::from_be_bytes(packet[0..2].try_into().unwrap());
    let proto_type = u16::from_be_bytes(packet[2..4].try_into().unwrap());
    let hw_len = packet[4] as usize;
    let proto_len = packet[5] as usize;
    let operation = u16::from_be_bytes(packet[6..8].try_into().unwrap());

    if hw_type != 1 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
        return None;
    }
    if packet.len() < 8 + 2 * (hw_len + proto_len) {
        return None;
    }
    let sender_mac = format_mac(&packet[8..14]);
    let sender_ip = Ipv4Addr::new(packet[14], packet[15], packet[16], packet[17]).to_string();
    let target_mac = format_mac(&packet[18..24]);
    let target_ip = Ipv4Addr::new(packet[24], packet[25], packet[26], packet[27]).to_string();

    let (source, destination, summary) = match operation {
        1 => (
            sender_ip.clone(),
            target_ip.clone(),
            format!("ARP who-has {target_ip} tell {sender_ip}"),
        ),
        2 => (
            sender_ip.clone(),
            target_ip.clone(),
            format!("ARP reply {sender_ip} is-at {sender_mac}"),
        ),
        _ => (
            sender_ip.clone(),
            target_ip.clone(),
            format!("ARP op {operation} {sender_ip} {ARROW} {target_ip}"),
        ),
    };

    Some(PacketAnalysis {
        source,
        destination,
        protocol: "ARP".to_string(),
        summary: format!(
            "{summary} ({} → {})",
            src_mac,
            if operation == 2 {
                target_mac
            } else {
                dst_mac.to_string()
            }
        ),
        layers: DecodedLayers::default(),
    })
}

fn map_ip_protocol(value: u8) -> &'static str {
    match value {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "ENCAP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "IP",
    }
}

fn describe_icmpv4(icmp_type: u8, icmp_code: u8) -> String {
    match (icmp_type, icmp_code) {
        (0, _) => "echo reply".to_string(),
        (3, 0) => "destination network unreachable".into(),
        (3, 1) => "destination host unreachable".into(),
        (3, 3) => "port unreachable".into(),
        (5, 1) => "redirect host".into(),
        (8, _) => "echo request".into(),
        (11, 0) => "time exceeded in transit".into(),
        (11, 1) => "fragment reassembly time exceeded".into(),
        _ => format!("type {icmp_type}, code {icmp_code}"),
    }
}

fn describe_icmpv6(icmp_type: u8, icmp_code: u8) -> String {
    match (icmp_type, icmp_code) {
        (1, 0) => "destination unreachable".into(),
        (2, 0) => "packet too big".into(),
        (3, 0) => "time exceeded".into(),
        (128, _) => "echo request".into(),
        (129, _) => "echo reply".into(),
        (133, _) => "router solicitation".into(),
        (134, _) => "router advertisement".into(),
        (135, _) => "neighbor solicitation".into(),
        (136, _) => "neighbor advertisement".into(),
        _ => format!("type {icmp_type}, code {icmp_code}"),
    }
}

fn format_port(address: &str, port: u16) -> String {
    format!("{address}:{port}")
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":")
}

fn process_raw_payload(data: &[u8]) -> PacketProcessingResult {
    if data.is_empty() {
        return PacketProcessingResult {
            packets: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };
    }
    let summary = if data.len() == 1 {
        "Raw payload (1 byte)".to_string()
    } else {
        format!("Raw payload ({} bytes)", data.len())
    };
    let packet = create_packet(
        PacketMetadata {
            time: "0.000000".to_string(),
            source: "upload".to_string(),
            destination: EM_DASH.to_string(),
            protocol: "RAW".to_string(),
            summary,
            length: data.len(),
            layers: None,
        },
        data,
    );
    PacketProcessingResult {
        packets: vec![packet],
        warnings: Vec::new(),
        errors: Vec::new(),
    }
}

#[wasm_bindgen]
pub fn process_packet(data: &[u8]) -> String {
    let result = if data.is_empty() {
        PacketProcessingResult {
            packets: Vec::new(),
            warnings: vec!["Empty payload provided".to_string()],
            errors: Vec::new(),
        }
    } else {
        match detect_format(data) {
            CaptureFormat::Pcap => match process_pcap(data) {
                Ok(result) => result,
                Err(err) => {
                    let mut fallback = process_raw_payload(data);
                    fallback.errors.push(err);
                    fallback
                }
            },
            CaptureFormat::PcapNg => match process_pcapng(data) {
                Ok(result) => result,
                Err(err) => {
                    let mut fallback = process_raw_payload(data);
                    fallback.errors.push(err);
                    fallback
                }
            },
            CaptureFormat::Raw => process_raw_payload(data),
        }
    };
    serialize_result(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_icmpv4_summary() {
        let layers = DecodedLayers {
            ipv4: Some(Ipv4Header {
                source: "192.168.1.10".to_string(),
                destination: "192.168.1.1".to_string(),
                protocol: 1,
                header_length: 20,
                total_length: 84,
                ttl: 64,
            }),
            icmp: Some(IcmpHeader {
                icmp_type: 8,
                icmp_code: 0,
                description: "Echo Request".to_string(),
                version: "ICMP".to_string(),
            }),
            ..Default::default()
        };

        let summary = build_summary_from_layers(&layers, "fallback".to_string());
        assert_eq!(summary, "ICMP 192.168.1.10 → 192.168.1.1 (Echo Request)");
    }

    #[test]
    fn builds_icmpv6_summary() {
        let layers = DecodedLayers {
            ipv6: Some(Ipv6Header {
                source: "2001:db8::1".to_string(),
                destination: "2001:db8::2".to_string(),
                next_header: 58,
                payload_length: 32,
                hop_limit: 64,
            }),
            icmp: Some(IcmpHeader {
                icmp_type: 128,
                icmp_code: 0,
                description: "Echo Request".to_string(),
                version: "ICMPv6".to_string(),
            }),
            ..Default::default()
        };

        let summary = build_summary_from_layers(&layers, "fallback".to_string());
        assert_eq!(summary, "ICMPv6 2001:db8::1 → 2001:db8::2 (Echo Request)");
    }

    #[test]
    fn uses_fallback_when_required_layer_missing() {
        let layers = DecodedLayers {
            icmp: Some(IcmpHeader {
                icmp_type: 3,
                icmp_code: 1,
                description: "Host Unreachable".to_string(),
                version: "ICMP".to_string(),
            }),
            ..Default::default()
        };

        let summary = build_summary_from_layers(&layers, "default summary".to_string());
        assert_eq!(summary, "default summary");
    }

    #[test]
    fn uses_fallback_for_unsupported_protocol() {
        let layers = DecodedLayers {
            ethernet: Some(EthernetHeader {
                source_mac: "00:11:22:33:44:55".to_string(),
                destination_mac: "66:77:88:99:aa:bb".to_string(),
                ethertype: 0x86DD,
            }),
            ..Default::default()
        };

        let summary = build_summary_from_layers(&layers, "unsupported".to_string());
        assert_eq!(summary, "unsupported");
    }
}
