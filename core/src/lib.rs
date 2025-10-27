use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use pcap_parser::{
    PcapError, PcapNGSlice, nom,
    pcapng::{Block, InterfaceDescriptionBlock},
    traits::PcapNGPacketBlock,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

const EM_DASH: &str = "—";
const ARROW: &str = "\u{2192}";

#[derive(Serialize)]
struct PacketSummary {
    info: String,
    summary: String,
    time: String,
    src: String,
    dst: String,
    protocol: String,
    length: usize,
    hex_preview: String,
    ascii_preview: String,
}

#[derive(Serialize)]
struct Packet {
    time: String,
    source: String,
    destination: String,
    protocol: String,
    length: usize,
    info: String,
    payload: Vec<u8>,
}

#[derive(Serialize)]
struct PacketProcessingResult {
    packets: Vec<Packet>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

struct PacketMetadata {
    time: String,
    source: String,
    destination: String,
    protocol: String,
    summary: String,
    length: usize,
}

#[derive(Clone, Copy)]
struct InterfaceInfo {
    linktype: u32,
    ts_offset: u64,
    ts_resolution: u64,
}

impl InterfaceInfo {
    fn from_block(block: &InterfaceDescriptionBlock<'_>) -> InterfaceInfo {
        let resolution = block.ts_resolution().unwrap_or(1_000_000);
        InterfaceInfo {
            linktype: block.linktype.0 as u32,
            ts_offset: block.ts_offset(),
            ts_resolution: resolution,
        }
    }
}

#[derive(Default)]
struct PacketAnalysis {
    source: String,
    destination: String,
    protocol: String,
    summary: String,
}

#[derive(Clone, Copy)]
enum CaptureFormat {
    Raw,
    Pcap,
    PcapNg,
}

#[derive(Clone, Copy)]
enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn read_u32(self, bytes: &[u8]) -> u32 {
        let array: [u8; 4] = bytes[..4].try_into().unwrap();
        match self {
            Endianness::Little => u32::from_le_bytes(array),
            Endianness::Big => u32::from_be_bytes(array),
        }
    }

    fn read_i32(self, bytes: &[u8]) -> i32 {
        let array: [u8; 4] = bytes[..4].try_into().unwrap();
        match self {
            Endianness::Little => i32::from_le_bytes(array),
            Endianness::Big => i32::from_be_bytes(array),
        }
    }
}

struct PcapHeaderInfo {
    endianness: Endianness,
    resolution: u64,
    timezone_offset: i32,
    linktype: u32,
    _snaplen: u32,
}

fn build_hex_preview(bytes: &[u8], max_len: usize) -> String {
    let preview_len = bytes.len().min(max_len);
    let mut parts = Vec::with_capacity(preview_len);
    for byte in bytes.iter().take(preview_len) {
        parts.push(format!("{:02X}", byte));
    }
    let mut preview = parts.join(" ");
    if bytes.len() > preview_len {
        preview.push_str(" …");
    }
    preview
}

fn build_ascii_preview(bytes: &[u8], max_len: usize) -> String {
    let preview_len = bytes.len().min(max_len);
    let mut preview = String::with_capacity(preview_len);
    for byte in bytes.iter().take(preview_len) {
        let ch = *byte;
        if (0x20..=0x7E).contains(&ch) {
            preview.push(ch as char);
        } else {
            preview.push('.');
        }
    }
    if bytes.len() > preview_len {
        preview.push('…');
    }
    preview
}

fn serialize_result(result: &PacketProcessingResult) -> String {
    serde_json::to_string(result)
        .unwrap_or_else(|_| "{\"packets\":[],\"warnings\":[],\"errors\":[]}".into())
}

fn detect_format(data: &[u8]) -> CaptureFormat {
    if data.len() < 4 {
        return CaptureFormat::Raw;
    }
    if data.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) {
        return CaptureFormat::PcapNg;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    match magic {
        0xA1B2_C3D4 | 0xA1B2_3C4D | 0xD4C3_B2A1 | 0x4D3C_B2A1 => CaptureFormat::Pcap,
        _ => CaptureFormat::Raw,
    }
}

fn parse_pcap_header(data: &[u8]) -> Result<(PcapHeaderInfo, usize), String> {
    if data.len() < 24 {
        return Err("PCAP data is too short".to_string());
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let (endianness, resolution) = match magic {
        0xA1B2_C3D4 => (Endianness::Little, 1_000_000),
        0xA1B2_3C4D => (Endianness::Little, 1_000_000_000),
        0xD4C3_B2A1 => (Endianness::Big, 1_000_000),
        0x4D3C_B2A1 => (Endianness::Big, 1_000_000_000),
        _ => return Err("Unrecognized PCAP header".to_string()),
    };
    let thiszone = endianness.read_i32(&data[8..12]);
    let snaplen = endianness.read_u32(&data[16..20]);
    let linktype = endianness.read_u32(&data[20..24]);
    Ok((
        PcapHeaderInfo {
            endianness,
            resolution,
            timezone_offset: thiszone,
            linktype,
            _snaplen: snaplen,
        },
        24,
    ))
}

fn format_timestamp(seconds: i64, fractional: u64, resolution: u64) -> String {
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
        if value % 10 != 0 {
            return None;
        }
        value /= 10;
        digits += 1;
    }
    Some(digits)
}

fn create_packet(meta: PacketMetadata, payload: &[u8]) -> Packet {
    let PacketMetadata {
        time,
        source,
        destination,
        protocol,
        summary,
        length,
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
        time,
        source,
        destination,
        protocol,
        length,
        info,
        payload: payload.to_vec(),
    }
}

fn analyze_payload(linktype: u32, payload: &[u8]) -> PacketAnalysis {
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
    let ethertype = u16::from_be_bytes(frame[12..14].try_into().unwrap());
    match ethertype {
        0x0800 => {
            if let Some(mut analysis) = parse_ipv4_packet(&frame[14..]) {
                if analysis.source == EM_DASH {
                    analysis.source = src_mac.clone();
                }
                if analysis.destination == EM_DASH {
                    analysis.destination = dst_mac.clone();
                }
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
    let total_length = u16::from_be_bytes(packet[2..4].try_into().unwrap()) as usize;
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
    };

    match protocol {
        6 | 17 | 132 => {
            if payload.len() >= 4 {
                let src_port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
                let dst_port = u16::from_be_bytes(payload[2..4].try_into().unwrap());
                analysis.source = format_port(&src_ip, src_port);
                analysis.destination = format_port(&dst_ip, dst_port);
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
                analysis.summary = format!("ICMP {src_ip} {ARROW} {dst_ip} ({description})");
            }
        }
        _ => {}
    }

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
    };

    match next_header {
        6 | 17 | 132 => {
            if payload.len() >= 4 {
                let src_port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
                let dst_port = u16::from_be_bytes(payload[2..4].try_into().unwrap());
                analysis.source = format_port(&src_ip, src_port);
                analysis.destination = format_port(&dst_ip, dst_port);
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
                analysis.summary = format!("ICMPv6 {src_ip} {ARROW} {dst_ip} ({description})");
            }
        }
        _ => {}
    }

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

fn describe_nom_error(err: nom::Err<PcapError<&[u8]>>) -> String {
    match err {
        nom::Err::Error(e) | nom::Err::Failure(e) => e.to_string(),
        nom::Err::Incomplete(_) => "Incomplete PCAPNG data".to_string(),
    }
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
        },
        data,
    );
    PacketProcessingResult {
        packets: vec![packet],
        warnings: Vec::new(),
        errors: Vec::new(),
    }
}

fn process_pcap(data: &[u8]) -> Result<PacketProcessingResult, String> {
    let (header, mut offset) = parse_pcap_header(data)?;
    let mut packets = Vec::new();
    let mut warnings = Vec::new();
    let mut index = 0usize;
    while offset + 16 <= data.len() {
        let block = &data[offset..offset + 16];
        offset += 16;
        let ts_sec = header.endianness.read_u32(&block[0..4]);
        let ts_frac = header.endianness.read_u32(&block[4..8]) as u64;
        let cap_len = header.endianness.read_u32(&block[8..12]) as usize;
        let orig_len = header.endianness.read_u32(&block[12..16]) as usize;
        if offset + cap_len > data.len() {
            warnings.push(format!(
                "Packet {} header exceeds capture length",
                index + 1
            ));
            break;
        }
        let payload = &data[offset..offset + cap_len];
        offset += cap_len;
        let mut analysis = analyze_payload(header.linktype, payload);
        if orig_len > cap_len {
            analysis.summary.push_str(" [truncated]");
            warnings.push(format!(
                "Packet {} truncated (captured {} of {} bytes)",
                index + 1,
                cap_len,
                orig_len
            ));
        }
        let timestamp_seconds = ts_sec as i64 + header.timezone_offset as i64;
        let metadata = PacketMetadata {
            time: format_timestamp(timestamp_seconds, ts_frac, header.resolution),
            source: analysis.source,
            destination: analysis.destination,
            protocol: analysis.protocol,
            summary: analysis.summary,
            length: cap_len,
        };
        packets.push(create_packet(metadata, payload));
        index += 1;
    }
    Ok(PacketProcessingResult {
        packets,
        warnings,
        errors: Vec::new(),
    })
}

fn process_pcapng(data: &[u8]) -> Result<PacketProcessingResult, String> {
    let mut slice = PcapNGSlice::from_slice(data).map_err(describe_nom_error)?;
    let mut packets = Vec::new();
    let mut warnings = Vec::new();
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    let mut packet_index = 0usize;
    while let Some(block) = slice.next() {
        match block {
            Ok(pcap_parser::PcapBlockOwned::NG(block)) => match block {
                Block::SectionHeader(_) => {
                    interfaces.clear();
                }
                Block::InterfaceDescription(idb) => {
                    interfaces.push(InterfaceInfo::from_block(&idb));
                }
                Block::EnhancedPacket(epb) => {
                    packet_index += 1;
                    let Some(info) = interfaces.get(epb.if_id as usize).copied() else {
                        warnings.push(format!(
                            "Enhanced packet {} references unknown interface {}",
                            packet_index, epb.if_id
                        ));
                        continue;
                    };
                    let payload = epb.packet_data();
                    let (ts_sec, ts_frac) = epb.decode_ts(info.ts_offset, info.ts_resolution);
                    let mut analysis = analyze_payload(info.linktype, payload);
                    if (epb.caplen as usize) < (epb.origlen as usize) {
                        analysis.summary.push_str(" [truncated]");
                        warnings.push(format!(
                            "Packet {} truncated (captured {} of {} bytes)",
                            packet_index, epb.caplen, epb.origlen
                        ));
                    }
                    let metadata = PacketMetadata {
                        time: format_timestamp(ts_sec as i64, ts_frac as u64, info.ts_resolution),
                        source: analysis.source,
                        destination: analysis.destination,
                        protocol: analysis.protocol,
                        summary: analysis.summary,
                        length: payload.len(),
                    };
                    packets.push(create_packet(metadata, payload));
                }
                Block::SimplePacket(spb) => {
                    packet_index += 1;
                    let info = interfaces.get(0).copied().unwrap_or(InterfaceInfo {
                        linktype: 1,
                        ts_offset: 0,
                        ts_resolution: 1_000_000,
                    });
                    let payload = spb.packet_data();
                    let mut analysis = analyze_payload(info.linktype, payload);
                    if (spb.origlen as usize) > payload.len() {
                        analysis.summary.push_str(" [truncated]");
                        warnings.push(format!(
                            "Packet {} truncated (captured {} of {} bytes)",
                            packet_index,
                            payload.len(),
                            spb.origlen
                        ));
                    }
                    let metadata = PacketMetadata {
                        time: "0.000000".to_string(),
                        source: analysis.source,
                        destination: analysis.destination,
                        protocol: analysis.protocol,
                        summary: analysis.summary,
                        length: payload.len(),
                    };
                    packets.push(create_packet(metadata, payload));
                }
                _ => {}
            },
            Ok(_) => {}
            Err(err) => {
                warnings.push(describe_nom_error(err));
                break;
            }
        }
    }
    Ok(PacketProcessingResult {
        packets,
        warnings,
        errors: Vec::new(),
    })
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
