use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct PacketSummary<'a> {
    info: &'a str,
    summary: &'a str,
    time: &'a str,
    src: &'a str,
    dst: &'a str,
    protocol: &'a str,
    length: usize,
    hex_preview: &'a str,
    ascii_preview: &'a str,
}

#[derive(Serialize)]
struct Packet<'a> {
    time: &'a str,
    source: &'a str,
    destination: &'a str,
    protocol: &'a str,
    length: usize,
    info: String,
    payload: Vec<u8>,
}

#[derive(Serialize)]
struct PacketProcessingResult<'a> {
    packets: Vec<Packet<'a>>,
    warnings: Vec<&'a str>,
    errors: Vec<&'a str>,
}

fn build_hex_preview(bytes: &[u8], max_len: usize) -> String {
    let preview_len = bytes.len().min(max_len);
    let mut preview = bytes
        .iter()
        .take(preview_len)
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ");

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
        preview.push_str("…");
    }

    preview
}

fn build_info_payload<'a>(
    total_bytes: usize,
    hex_preview: &'a str,
    ascii_preview: &'a str,
) -> PacketSummary<'a> {
    let base_summary = if total_bytes == 1 {
        "Analyzed 1 byte"
    } else {
        "Analyzed payload"
    };

    PacketSummary {
        info: base_summary,
        summary: base_summary,
        time: "0.000000",
        src: "upload",
        dst: "—",
        protocol: "RAW",
        length: total_bytes,
        hex_preview,
        ascii_preview,
    }
}

fn serialize_result(result: &PacketProcessingResult) -> String {
    serde_json::to_string(result)
        .unwrap_or_else(|_| "{\"packets\":[],\"warnings\":[],\"errors\":[]}".into())
}

/// Process a packet payload and return a structured JSON response.
///
/// The output mirrors the shape that the frontend expects from the
/// WebAssembly module: a JSON object with `packets`, `warnings`, and
/// `errors` arrays. Each packet includes the raw payload bytes alongside
/// a JSON encoded summary string that can be parsed for additional
/// metadata.
#[wasm_bindgen]
pub fn process_packet(data: &[u8]) -> String {
    if data.is_empty() {
        return serialize_result(&PacketProcessingResult {
            packets: Vec::new(),
            warnings: vec!["Empty payload provided"],
            errors: Vec::new(),
        });
    }

    let hex_preview = build_hex_preview(data, 32);
    let ascii_preview = build_ascii_preview(data, 32);
    let info_payload = build_info_payload(data.len(), &hex_preview, &ascii_preview);

    let packet = Packet {
        time: info_payload.time,
        source: "upload",
        destination: "—",
        protocol: info_payload.protocol,
        length: data.len(),
        info: serde_json::to_string(&info_payload)
            .unwrap_or_else(|_| "{\"info\":\"Analyzed payload\"}".into()),
        payload: data.to_vec(),
    };

    serialize_result(&PacketProcessingResult {
        packets: vec![packet],
        warnings: Vec::new(),
        errors: Vec::new(),
    })
}
