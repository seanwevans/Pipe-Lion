//! PCAPNG parsing: walks the block stream, tracks per-interface link types and
//! timestamp resolutions, and turns Enhanced/Simple Packet Blocks into `Packet`s.

use pcap_parser::{
    PcapError, PcapNGSlice, nom,
    pcapng::{Block, InterfaceDescriptionBlock},
    traits::PcapNGPacketBlock,
};

use crate::models::{PacketMetadata, PacketProcessingResult};
use crate::{analyze_payload, create_packet, format_timestamp};

#[derive(Clone, Copy)]
pub(crate) struct InterfaceInfo {
    pub(crate) linktype: u32,
    pub(crate) ts_offset: u64,
    pub(crate) ts_resolution: u64,
}

impl InterfaceInfo {
    pub(crate) fn from_block(block: &InterfaceDescriptionBlock<'_>) -> InterfaceInfo {
        let resolution = block.ts_resolution().unwrap_or(1_000_000);
        InterfaceInfo {
            linktype: block.linktype.0 as u32,
            ts_offset: block.ts_offset(),
            ts_resolution: resolution,
        }
    }
}
pub(crate) fn describe_nom_error(err: nom::Err<PcapError<&[u8]>>) -> String {
    match err {
        nom::Err::Error(e) | nom::Err::Failure(e) => e.to_string(),
        nom::Err::Incomplete(_) => "Incomplete PCAPNG data".to_string(),
    }
}
pub(crate) fn process_pcapng(data: &[u8]) -> Result<PacketProcessingResult, String> {
    let mut slice = PcapNGSlice::from_slice(data).map_err(describe_nom_error)?;
    let mut packets = Vec::new();
    let mut warnings = Vec::new();
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    let mut packet_index = 0usize;
    for block in &mut slice {
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
                        layers: Some(analysis.layers),
                    };
                    packets.push(create_packet(metadata, payload));
                }
                Block::SimplePacket(spb) => {
                    packet_index += 1;
                    let info = interfaces.first().copied().unwrap_or(InterfaceInfo {
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
                        layers: Some(analysis.layers),
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
#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet + IPv4 + UDP (192.168.0.1:53 -> 192.168.0.2:4096), 42 bytes.
    fn sample_frame() -> Vec<u8> {
        let mut frame = vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // destination MAC
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // source MAC
            0x08, 0x00, // EtherType: IPv4
        ];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1C, // version/IHL, DSCP, total length (28)
            0x00, 0x00, 0x00, 0x00, // identification, flags/fragment
            0x40, 0x11, 0x00, 0x00, // TTL, protocol (UDP), checksum
            192, 168, 0, 1, // source
            192, 168, 0, 2, // destination
        ]);
        frame.extend_from_slice(&[
            0x00, 0x35, // source port 53
            0x10, 0x00, // destination port 4096
            0x00, 0x08, // length
            0x00, 0x00, // checksum
        ]);
        frame
    }

    fn section_header() -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        block.extend_from_slice(&28u32.to_le_bytes());
        block.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        block.extend_from_slice(&1u16.to_le_bytes()); // major version
        block.extend_from_slice(&0u16.to_le_bytes()); // minor version
        block.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
        block.extend_from_slice(&28u32.to_le_bytes());
        block
    }

    fn interface_description(linktype: u16) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&1u32.to_le_bytes());
        block.extend_from_slice(&20u32.to_le_bytes());
        block.extend_from_slice(&linktype.to_le_bytes());
        block.extend_from_slice(&0u16.to_le_bytes()); // reserved
        block.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        block.extend_from_slice(&20u32.to_le_bytes());
        block
    }

    fn enhanced_packet(
        if_id: u32,
        timestamp_micros: u64,
        payload: &[u8],
        orig_len: u32,
    ) -> Vec<u8> {
        let padded = payload.len().next_multiple_of(4);
        let total = 32 + padded as u32;
        let mut block = Vec::new();
        block.extend_from_slice(&6u32.to_le_bytes());
        block.extend_from_slice(&total.to_le_bytes());
        block.extend_from_slice(&if_id.to_le_bytes());
        block.extend_from_slice(&((timestamp_micros >> 32) as u32).to_le_bytes());
        block.extend_from_slice(&((timestamp_micros & 0xFFFF_FFFF) as u32).to_le_bytes());
        block.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        block.extend_from_slice(&orig_len.to_le_bytes());
        block.extend_from_slice(payload);
        block.resize(block.len() + (padded - payload.len()), 0);
        block.extend_from_slice(&total.to_le_bytes());
        block
    }

    fn capture(blocks: &[Vec<u8>]) -> Vec<u8> {
        blocks.iter().flatten().copied().collect()
    }

    #[test]
    fn decodes_enhanced_packet_block() {
        let frame = sample_frame();
        let data = capture(&[
            section_header(),
            interface_description(1),
            enhanced_packet(0, 1_500_000, &frame, frame.len() as u32),
        ]);

        let result = process_pcapng(&data).expect("pcapng parses");

        assert_eq!(result.packets.len(), 1);
        assert!(result.warnings.is_empty());
        let packet = &result.packets[0];
        assert_eq!(packet.protocol, "UDP");
        assert_eq!(packet.source, "192.168.0.1:53");
        assert_eq!(packet.destination, "192.168.0.2:4096");
        assert_eq!(packet.length, frame.len());
        assert_eq!(packet.time, "1.500000");
        assert_eq!(packet.payload, frame);
    }

    #[test]
    fn warns_when_packet_is_truncated() {
        let frame = sample_frame();
        let data = capture(&[
            section_header(),
            interface_description(1),
            enhanced_packet(0, 0, &frame, frame.len() as u32 * 2),
        ]);

        let result = process_pcapng(&data).expect("pcapng parses");

        assert_eq!(result.packets.len(), 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("truncated"));
        assert!(result.packets[0].info.contains("[truncated]"));
    }

    #[test]
    fn warns_when_interface_is_unknown() {
        let frame = sample_frame();
        let data = capture(&[
            section_header(),
            interface_description(1),
            enhanced_packet(7, 0, &frame, frame.len() as u32),
        ]);

        let result = process_pcapng(&data).expect("pcapng parses");

        assert!(result.packets.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("unknown interface 7"));
    }

    #[test]
    fn rejects_data_that_is_not_pcapng() {
        assert!(process_pcapng(&[0u8; 16]).is_err());
    }
}
