use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

mod application;
mod capture;
mod core_format;
mod decode;
mod dns;
mod models;
mod pcap;
mod pcapng;
mod preview;
mod tls;

use crate::decode::build_summary_from_layers;
use crate::models::{
    DecodedLayers, EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, Packet, PacketAnalysis,
    PacketMetadata, PacketProcessingResult, TcpHeader, UdpHeader,
};
use crate::preview::{build_ascii_preview, build_hex_preview};

pub use crate::capture::{CaptureHandle, parse};

pub(crate) const EM_DASH: &str = "\u{2014}";
pub(crate) const ARROW: &str = "\u{2192}";

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

    Packet {
        layers,
        time,
        source,
        destination,
        protocol,
        length,
        info: summary,
        hex_preview: build_hex_preview(payload, 32),
        ascii_preview: build_ascii_preview(payload, 32),
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
                record_transport(protocol, src_port, dst_port, payload, &mut analysis.layers);
                let dissection = application::dissect(
                    protocol,
                    src_port,
                    dst_port,
                    payload,
                    &mut analysis.layers,
                );
                if let Some(dissection) = &dissection {
                    analysis.protocol = dissection.protocol.to_string();
                }
                analysis.summary = describe_transport(
                    &analysis.protocol,
                    &analysis.source,
                    &analysis.destination,
                    dissection.as_ref(),
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
                record_transport(
                    next_header,
                    src_port,
                    dst_port,
                    payload,
                    &mut analysis.layers,
                );
                let dissection = application::dissect(
                    next_header,
                    src_port,
                    dst_port,
                    payload,
                    &mut analysis.layers,
                );
                if let Some(dissection) = &dissection {
                    analysis.protocol = dissection.protocol.to_string();
                }
                analysis.summary = describe_transport(
                    &analysis.protocol,
                    &analysis.source,
                    &analysis.destination,
                    dissection.as_ref(),
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

/// Records the TCP or UDP layer for a transport segment. SCTP gets ports in the
/// address columns but has no dedicated layer struct yet.
fn record_transport(
    ip_protocol: u8,
    source_port: u16,
    destination_port: u16,
    segment: &[u8],
    layers: &mut DecodedLayers,
) {
    match ip_protocol {
        6 => {
            layers.tcp = Some(TcpHeader {
                source_port,
                destination_port,
                header_length: application::tcp_header_length(segment).unwrap_or(0),
            });
        }
        17 => {
            let length = segment
                .get(4..6)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u16::from_be_bytes)
                .unwrap_or(0);
            layers.udp = Some(UdpHeader {
                source_port,
                destination_port,
                length,
            });
        }
        _ => {}
    }
}

fn describe_transport(
    protocol: &str,
    source: &str,
    destination: &str,
    dissection: Option<&application::Dissection>,
) -> String {
    match dissection {
        Some(dissection) => format!(
            "{protocol} {source} {ARROW} {destination} {}",
            dissection.detail
        ),
        None => format!("{protocol} {source} {ARROW} {destination}"),
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

pub(crate) fn process_raw_payload(data: &[u8]) -> PacketProcessingResult {
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

    /// UDP segment carrying a DNS query for `example.com`.
    fn dns_over_udp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut message = vec![0x1A, 0x2B, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[7]);
        message.extend_from_slice(b"example");
        message.extend_from_slice(&[3]);
        message.extend_from_slice(b"com");
        message.push(0);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());

        let mut segment = source_port.to_be_bytes().to_vec();
        segment.extend_from_slice(&destination_port.to_be_bytes());
        segment.extend_from_slice(&((message.len() + 8) as u16).to_be_bytes());
        segment.extend_from_slice(&0u16.to_be_bytes());
        segment.extend_from_slice(&message);
        segment
    }

    /// TCP segment carrying a minimal TLS 1.2 ClientHello for `example.com`.
    fn tls_over_tcp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let host = b"example.com";
        let mut sni_entry = vec![0u8];
        sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(host);
        let mut sni_body = (sni_entry.len() as u16).to_be_bytes().to_vec();
        sni_body.extend_from_slice(&sni_entry);
        let mut extensions = 0u16.to_be_bytes().to_vec();
        extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_body);

        let mut hello = 0x0303u16.to_be_bytes().to_vec();
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![1u8];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let mut segment = source_port.to_be_bytes().to_vec();
        segment.extend_from_slice(&destination_port.to_be_bytes());
        segment.extend_from_slice(&[0; 8]);
        segment.push(5 << 4);
        segment.push(0x18);
        segment.extend_from_slice(&[0; 6]);
        segment.extend_from_slice(&record);
        segment
    }

    fn ipv4_packet(protocol: u8, segment: &[u8]) -> Vec<u8> {
        let total_length = (20 + segment.len()) as u16;
        let mut packet = vec![0x45, 0x00];
        packet.extend_from_slice(&total_length.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&[10, 0, 0, 5]);
        packet.extend_from_slice(&[1, 1, 1, 1]);
        packet.extend_from_slice(segment);
        packet
    }

    fn ipv6_packet(next_header: u8, segment: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        packet.push(next_header);
        packet.push(64);
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(segment);
        packet
    }

    #[test]
    fn labels_dns_over_ipv4_udp() {
        let packet = ipv4_packet(17, &dns_over_udp(51234, 53));

        let analysis = parse_ipv4_packet(&packet).expect("IPv4 packet parses");

        assert_eq!(analysis.protocol, "DNS");
        assert_eq!(analysis.source, "10.0.0.5:51234");
        assert_eq!(
            analysis.summary,
            "DNS 10.0.0.5:51234 \u{2192} 1.1.1.1:53 Standard query 0x1a2b A example.com"
        );
        let dns = analysis.layers.dns.expect("DNS layer is recorded");
        assert_eq!(dns.questions[0].name, "example.com");
    }

    #[test]
    fn labels_mdns_over_ipv6_udp() {
        let packet = ipv6_packet(17, &dns_over_udp(5353, 5353));

        let analysis = parse_ipv6_packet(&packet).expect("IPv6 packet parses");

        assert_eq!(analysis.protocol, "DNS");
        assert!(
            analysis
                .summary
                .contains("Standard query 0x1a2b A example.com")
        );
    }

    #[test]
    fn labels_tls_client_hello_over_ipv4_tcp() {
        let packet = ipv4_packet(6, &tls_over_tcp(51234, 443));

        let analysis = parse_ipv4_packet(&packet).expect("IPv4 packet parses");

        assert_eq!(analysis.protocol, "TLS");
        assert_eq!(
            analysis.summary,
            "TLS 10.0.0.5:51234 \u{2192} 1.1.1.1:443 TLSv1.2 Client Hello (SNI=example.com)"
        );
        let tls = analysis.layers.tls.expect("TLS layer is recorded");
        assert_eq!(
            tls.client_hello
                .expect("client hello")
                .server_name
                .as_deref(),
            Some("example.com")
        );
        assert_eq!(
            analysis
                .layers
                .tcp
                .expect("TCP layer is recorded")
                .header_length,
            20
        );
    }

    #[test]
    fn labels_tls_on_a_non_standard_port() {
        let packet = ipv4_packet(6, &tls_over_tcp(51234, 8443));

        let analysis = parse_ipv4_packet(&packet).expect("IPv4 packet parses");

        assert_eq!(analysis.protocol, "TLS");
    }

    #[test]
    fn leaves_plain_tcp_alone() {
        let mut segment = 51234u16.to_be_bytes().to_vec();
        segment.extend_from_slice(&80u16.to_be_bytes());
        segment.extend_from_slice(&[0; 8]);
        segment.push(5 << 4);
        segment.push(0x18);
        segment.extend_from_slice(&[0; 6]);
        segment.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let packet = ipv4_packet(6, &segment);

        let analysis = parse_ipv4_packet(&packet).expect("IPv4 packet parses");

        assert_eq!(analysis.protocol, "TCP");
        assert_eq!(analysis.summary, "TCP 10.0.0.5:51234 \u{2192} 1.1.1.1:80");
        assert!(analysis.layers.tls.is_none());
        assert!(analysis.layers.dns.is_none());
    }

    #[test]
    fn packet_info_is_the_summary_not_a_json_blob() {
        let packet = ipv4_packet(17, &dns_over_udp(51234, 53));
        let analysis = parse_ipv4_packet(&packet).expect("IPv4 packet parses");
        let summary = analysis.summary.clone();

        let built = create_packet(
            PacketMetadata {
                time: "0.000000".to_string(),
                source: analysis.source,
                destination: analysis.destination,
                protocol: analysis.protocol,
                summary: analysis.summary,
                length: packet.len(),
                layers: Some(analysis.layers),
            },
            &packet,
        );

        assert_eq!(built.info, summary);
        assert!(!built.info.starts_with('{'));
        assert!(built.hex_preview.starts_with("45 00"));
    }
}
