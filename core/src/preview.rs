pub fn build_hex_preview(bytes: &[u8], max_len: usize) -> String {
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

pub fn build_ascii_preview(bytes: &[u8], max_len: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_preview_truncates() {
        assert_eq!(build_hex_preview(&[0, 1, 2], 2), "00 01 …");
    }
    #[test]
    fn ascii_preview_maps_non_printable() {
        assert_eq!(build_ascii_preview(&[65, 0, 66], 3), "A.B");
    }
}
