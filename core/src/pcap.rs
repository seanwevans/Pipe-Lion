//! Classic libpcap (`.pcap`) parsing: file header plus the flat record stream.

use std::convert::TryInto;

use crate::models::{PacketMetadata, PacketProcessingResult};
use crate::{analyze_payload, create_packet, format_timestamp};

#[derive(Clone, Copy)]
pub enum Endianness {
    Little,
    Big,
}
impl Endianness {
    pub fn read_u32(self, bytes: &[u8]) -> u32 {
        let a: [u8; 4] = bytes[..4].try_into().unwrap();
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }
    pub fn read_i32(self, bytes: &[u8]) -> i32 {
        let a: [u8; 4] = bytes[..4].try_into().unwrap();
        match self {
            Self::Little => i32::from_le_bytes(a),
            Self::Big => i32::from_be_bytes(a),
        }
    }
}

pub struct PcapHeaderInfo {
    pub endianness: Endianness,
    pub resolution: u64,
    pub timezone_offset: i32,
    pub linktype: u32,
    pub _snaplen: u32,
}

pub fn parse_pcap_header(data: &[u8]) -> Result<(PcapHeaderInfo, usize), String> {
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

pub(crate) fn process_pcap(data: &[u8]) -> Result<PacketProcessingResult, String> {
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
            layers: Some(analysis.layers),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet + IPv4 + ICMP echo request (10.0.0.1 -> 10.0.0.2).
    fn sample_frame() -> Vec<u8> {
        let mut frame = vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // destination MAC
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // source MAC
            0x08, 0x00, // EtherType: IPv4
        ];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1C, // version/IHL, DSCP, total length (28)
            0x00, 0x00, 0x00, 0x00, // identification, flags/fragment
            0x40, 0x01, 0x00, 0x00, // TTL, protocol (ICMP), checksum
            10, 0, 0, 1, // source
            10, 0, 0, 2, // destination
        ]);
        frame.extend_from_slice(&[
            0x08, 0x00, // echo request
            0x00, 0x00, // checksum
            0x00, 0x01, 0x00, 0x01, // identifier, sequence
        ]);
        frame
    }

    fn file_header(linktype: u32) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        header.extend_from_slice(&2u16.to_le_bytes()); // major version
        header.extend_from_slice(&4u16.to_le_bytes()); // minor version
        header.extend_from_slice(&0i32.to_le_bytes()); // timezone offset
        header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        header.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        header.extend_from_slice(&linktype.to_le_bytes());
        header
    }

    fn record(ts_sec: u32, ts_usec: u32, payload: &[u8], orig_len: u32) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&ts_sec.to_le_bytes());
        block.extend_from_slice(&ts_usec.to_le_bytes());
        block.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        block.extend_from_slice(&orig_len.to_le_bytes());
        block.extend_from_slice(payload);
        block
    }

    fn capture(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    #[test]
    fn parses_header_fields() {
        let (header, offset) = parse_pcap_header(&file_header(1)).expect("header parses");

        assert_eq!(offset, 24);
        assert_eq!(header.linktype, 1);
        assert_eq!(header.resolution, 1_000_000);
        assert!(matches!(header.endianness, Endianness::Little));
    }

    #[test]
    fn rejects_unknown_magic() {
        let mut data = file_header(1);
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        assert!(parse_pcap_header(&data).is_err());
    }

    #[test]
    fn decodes_records_in_order() {
        let frame = sample_frame();
        let data = capture(&[
            file_header(1),
            record(1, 250_000, &frame, frame.len() as u32),
            record(2, 0, &frame, frame.len() as u32),
        ]);

        let result = process_pcap(&data).expect("capture parses");

        assert_eq!(result.packets.len(), 2);
        assert!(result.warnings.is_empty());
        assert_eq!(result.packets[0].time, "1.250000");
        assert_eq!(result.packets[1].time, "2.000000");
        assert_eq!(result.packets[0].protocol, "ICMP");
        assert_eq!(result.packets[0].source, "10.0.0.1");
        assert_eq!(result.packets[0].destination, "10.0.0.2");
        assert!(result.packets[0].info.contains("echo request"));
    }

    #[test]
    fn warns_when_a_record_runs_past_the_end_of_the_file() {
        let frame = sample_frame();
        let mut data = capture(&[file_header(1), record(1, 0, &frame, frame.len() as u32)]);
        data.truncate(data.len() - 4);

        let result = process_pcap(&data).expect("capture parses");

        assert!(result.packets.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("exceeds capture length"));
    }
}
