//! The Wasm-facing capture handle.
//!
//! Parsing hands JavaScript an opaque handle rather than a serialized capture.
//! Packets stay in linear memory and cross the boundary in windows, so peak
//! memory is proportional to the window the UI is showing, not to the file.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::core_format::{CaptureFormat, detect_format};
use crate::models::{DecodedLayers, Packet, PacketProcessingResult};
use crate::pcap::process_pcap;
use crate::pcapng::process_pcapng;
use crate::process_raw_payload;

/// One row of the packet list. Deliberately excludes `payload`: bytes are the
/// bulk of a capture and serializing them as a JSON array of integers costs
/// roughly four characters per byte. Callers that need them ask for one packet
/// at a time via [`CaptureHandle::payload`], which copies raw bytes instead.
#[derive(Serialize)]
struct PacketRow<'a> {
    index: usize,
    time: &'a str,
    source: &'a str,
    destination: &'a str,
    protocol: &'a str,
    length: usize,
    info: &'a str,
    hex_preview: &'a str,
    ascii_preview: &'a str,
    payload_length: usize,
    layers: Option<&'a DecodedLayers>,
}

impl<'a> PacketRow<'a> {
    fn new(index: usize, packet: &'a Packet) -> PacketRow<'a> {
        PacketRow {
            index,
            time: &packet.time,
            source: &packet.source,
            destination: &packet.destination,
            protocol: &packet.protocol,
            length: packet.length,
            info: &packet.info,
            hex_preview: &packet.hex_preview,
            ascii_preview: &packet.ascii_preview,
            payload_length: packet.payload.len(),
            layers: packet.layers.as_ref(),
        }
    }
}

/// A parsed capture, owned by Wasm linear memory.
///
/// JavaScript holds this as an opaque handle and must call `free()` when done;
/// dropping the reference without freeing leaks the whole capture.
#[wasm_bindgen]
pub struct CaptureHandle {
    pub(crate) packets: Vec<Packet>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[wasm_bindgen]
impl CaptureHandle {
    /// Number of packets in the capture.
    #[wasm_bindgen(getter)]
    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Non-fatal parse diagnostics.
    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    /// Fatal parse errors. A capture with errors may still hold packets.
    #[wasm_bindgen(getter)]
    pub fn errors(&self) -> Vec<String> {
        self.errors.clone()
    }

    /// A window of packet rows as a JSON array, clamped to the capture. An
    /// out-of-range offset yields `[]` rather than an error, so a caller paging
    /// to the end needs no separate bounds check.
    pub fn packets(&self, offset: usize, count: usize) -> String {
        let end = offset.saturating_add(count).min(self.packets.len());
        let rows: Vec<PacketRow<'_>> = match self.packets.get(offset..end) {
            Some(window) => window
                .iter()
                .enumerate()
                .map(|(position, packet)| PacketRow::new(offset + position, packet))
                .collect(),
            None => Vec::new(),
        };
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
    }

    /// Raw bytes of one packet, copied straight out of linear memory as a
    /// `Uint8Array`. `None` for an out-of-range index.
    pub fn payload(&self, index: usize) -> Option<Vec<u8>> {
        self.packets.get(index).map(|packet| packet.payload.clone())
    }
}

impl From<PacketProcessingResult> for CaptureHandle {
    fn from(result: PacketProcessingResult) -> CaptureHandle {
        CaptureHandle {
            packets: result.packets,
            warnings: result.warnings,
            errors: result.errors,
        }
    }
}

/// Parses a capture and returns a handle to it.
///
/// Unparseable input is never an error: the bytes come back as a single raw
/// packet with the parse failure recorded in `errors`.
#[wasm_bindgen]
pub fn parse(data: &[u8]) -> CaptureHandle {
    if data.is_empty() {
        return CaptureHandle {
            packets: Vec::new(),
            warnings: vec!["Empty payload provided".to_string()],
            errors: Vec::new(),
        };
    }

    let result = match detect_format(data) {
        CaptureFormat::Pcap => fall_back_to_raw(process_pcap(data), data),
        CaptureFormat::PcapNg => fall_back_to_raw(process_pcapng(data), data),
        CaptureFormat::Raw => process_raw_payload(data),
    };
    result.into()
}

fn fall_back_to_raw(
    result: Result<PacketProcessingResult, String>,
    data: &[u8],
) -> PacketProcessingResult {
    match result {
        Ok(result) => result,
        Err(err) => {
            let mut fallback = process_raw_payload(data);
            fallback.errors.push(err);
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Ethernet + IPv4 + ICMP echo request, wrapped in a two-record pcap file.
    fn sample_capture() -> Vec<u8> {
        let mut frame = vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00,
        ];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ]);
        frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);

        let mut data = Vec::new();
        data.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        for seconds in 1..=3u32 {
            data.extend_from_slice(&seconds.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            data.extend_from_slice(&frame);
        }
        data
    }

    fn rows(json: &str) -> Vec<Value> {
        serde_json::from_str(json).expect("rows are valid JSON")
    }

    #[test]
    fn parses_a_capture_into_a_handle() {
        let handle = parse(&sample_capture());

        assert_eq!(handle.packet_count(), 3);
        assert!(handle.warnings().is_empty());
        assert!(handle.errors().is_empty());
    }

    #[test]
    fn returns_the_requested_window_with_absolute_indices() {
        let handle = parse(&sample_capture());

        let window = rows(&handle.packets(1, 2));

        assert_eq!(window.len(), 2);
        assert_eq!(window[0]["index"], 1);
        assert_eq!(window[1]["index"], 2);
        assert_eq!(window[0]["time"], "2.000000");
        assert_eq!(window[0]["protocol"], "ICMP");
        assert_eq!(window[0]["source"], "10.0.0.1");
    }

    #[test]
    fn clamps_a_window_that_runs_past_the_end() {
        let handle = parse(&sample_capture());

        assert_eq!(rows(&handle.packets(2, 100)).len(), 1);
        assert!(rows(&handle.packets(3, 10)).is_empty());
        assert!(rows(&handle.packets(999, 10)).is_empty());
        assert!(rows(&handle.packets(0, 0)).is_empty());
    }

    #[test]
    fn does_not_overflow_on_an_absurd_window() {
        let handle = parse(&sample_capture());

        assert_eq!(rows(&handle.packets(1, usize::MAX)).len(), 2);
    }

    #[test]
    fn rows_carry_a_payload_length_but_not_the_payload() {
        let handle = parse(&sample_capture());

        let window = rows(&handle.packets(0, 1));

        assert_eq!(window[0]["payload_length"], 42);
        assert!(window[0].get("payload").is_none());
        assert_eq!(window[0]["hex_preview"].as_str().unwrap()[..5], *"11 22");
    }

    #[test]
    fn payloads_are_fetched_one_packet_at_a_time() {
        let handle = parse(&sample_capture());

        let payload = handle.payload(0).expect("packet 0 has a payload");

        assert_eq!(payload.len(), 42);
        assert_eq!(&payload[..2], &[0x11, 0x22]);
        assert!(handle.payload(3).is_none());
    }

    #[test]
    fn reports_an_empty_upload_as_a_warning() {
        let handle = parse(&[]);

        assert_eq!(handle.packet_count(), 0);
        assert_eq!(
            handle.warnings(),
            vec!["Empty payload provided".to_string()]
        );
    }

    #[test]
    fn falls_back_to_a_raw_packet_when_the_header_is_unparseable() {
        // pcap magic, then a file too short to hold a header.
        let mut data = 0xA1B2_C3D4u32.to_le_bytes().to_vec();
        data.extend_from_slice(&[0xFF; 8]);

        let handle = parse(&data);

        assert_eq!(handle.packet_count(), 1);
        assert_eq!(handle.errors().len(), 1);
        assert_eq!(rows(&handle.packets(0, 1))[0]["protocol"], "RAW");
    }

    #[test]
    fn treats_unrecognized_bytes_as_a_single_raw_packet() {
        let handle = parse(b"not a capture at all");

        assert_eq!(handle.packet_count(), 1);
        assert!(handle.errors().is_empty());
        assert_eq!(rows(&handle.packets(0, 1))[0]["protocol"], "RAW");
    }
}
