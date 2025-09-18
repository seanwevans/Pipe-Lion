use wasm_bindgen::prelude::*;

/// Process a packet payload and return a placeholder response.
///
/// This function will eventually parse the provided bytes and produce
/// structured information for the UI. For now it only returns a string
/// that echoes the length of the payload.
#[wasm_bindgen]
pub fn process_packet(data: &[u8]) -> String {
    format!("Received {} bytes", data.len())
}
