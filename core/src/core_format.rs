use std::convert::TryInto;

#[derive(Clone, Copy)]
pub enum CaptureFormat { Raw, Pcap, PcapNg }

pub fn detect_format(data: &[u8]) -> CaptureFormat {
    if data.len() < 4 { return CaptureFormat::Raw; }
    if data.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) { return CaptureFormat::PcapNg; }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    match magic { 0xA1B2_C3D4 | 0xA1B2_3C4D | 0xD4C3_B2A1 | 0x4D3C_B2A1 => CaptureFormat::Pcap, _ => CaptureFormat::Raw }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_pcapng() { assert!(matches!(detect_format(&[0x0A,0x0D,0x0D,0x0A]), CaptureFormat::PcapNg)); }
}
