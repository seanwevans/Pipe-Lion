//! TLS record-layer dissection, with a full ClientHello parse.
//!
//! ClientHello is the one handshake message worth decoding in a browser tool:
//! it is unencrypted by definition, it carries the SNI hostname and the ALPN
//! list, and it is self-contained inside the first record of a connection.
//! Everything after it is either encrypted or needs session state we do not keep.

use crate::models::{TlsClientHello, TlsRecord};

const RECORD_HEADER_LEN: usize = 5;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const SNI_HOST_NAME: u8 = 0;

/// Cheap check used to decide whether a TCP segment is worth handing to
/// [`parse`]: a plausible content type followed by a `3.x` legacy version.
pub(crate) fn looks_like_record(segment: &[u8]) -> bool {
    segment.len() >= RECORD_HEADER_LEN
        && matches!(segment[0], 20..=23)
        && segment[1] == 3
        && segment[2] <= 4
}

pub(crate) fn parse(segment: &[u8]) -> Option<TlsRecord> {
    if !looks_like_record(segment) {
        return None;
    }

    let content_type = segment[0];
    let length = u16::from_be_bytes([segment[3], segment[4]]) as usize;
    // A record may be cut short by the snaplen; decode what is present.
    let available = segment.len() - RECORD_HEADER_LEN;
    let body = &segment[RECORD_HEADER_LEN..RECORD_HEADER_LEN + length.min(available)];

    let mut record = TlsRecord {
        content_type: describe_content_type(content_type).to_string(),
        version: describe_version(u16::from_be_bytes([segment[1], segment[2]])),
        handshake_type: None,
        client_hello: None,
    };

    if content_type == CONTENT_TYPE_HANDSHAKE
        && let Some(handshake_type) = body.first().copied()
    {
        record.handshake_type = Some(describe_handshake_type(handshake_type).to_string());
        if handshake_type == HANDSHAKE_CLIENT_HELLO {
            record.client_hello = parse_client_hello(body);
        }
    }

    Some(record)
}

/// Wireshark-style Info text, e.g. `TLSv1.3 Client Hello (SNI=example.com)`.
pub(crate) fn describe(record: &TlsRecord) -> String {
    let version = record
        .client_hello
        .as_ref()
        .map(|hello| hello.version.clone())
        .unwrap_or_else(|| record.version.clone());

    let mut text = version;
    match (&record.handshake_type, &record.client_hello) {
        (_, Some(hello)) => {
            text.push_str(" Client Hello");
            if let Some(name) = &hello.server_name {
                text.push_str(&format!(" (SNI={name})"));
            }
        }
        (Some(handshake_type), None) => {
            text.push(' ');
            text.push_str(handshake_type);
        }
        (None, None) => {
            text.push(' ');
            text.push_str(&record.content_type);
        }
    }
    text
}

fn parse_client_hello(body: &[u8]) -> Option<TlsClientHello> {
    // handshake type (1) + length (3) + client_version (2) + random (32)
    let mut cursor = Cursor::new(body);
    cursor.skip(4)?;
    let legacy_version = cursor.u16()?;
    cursor.skip(32)?;

    let session_id_len = cursor.u8()? as usize;
    cursor.skip(session_id_len)?;

    let cipher_suites_len = cursor.u16()? as usize;
    cursor.skip(cipher_suites_len)?;

    let compression_len = cursor.u8()? as usize;
    cursor.skip(compression_len)?;

    let mut hello = TlsClientHello {
        version: describe_version(legacy_version),
        server_name: None,
        alpn: Vec::new(),
    };

    // Extensions are optional in the wire format (and may be truncated away).
    let Some(extensions_len) = cursor.u16() else {
        return Some(hello);
    };
    let extensions = cursor.take(extensions_len as usize)?;
    read_extensions(extensions, &mut hello);
    Some(hello)
}

fn read_extensions(extensions: &[u8], hello: &mut TlsClientHello) {
    let mut cursor = Cursor::new(extensions);
    while let (Some(kind), Some(length)) = (cursor.u16(), cursor.u16()) {
        let Some(body) = cursor.take(length as usize) else {
            return;
        };
        match kind {
            EXT_SERVER_NAME => hello.server_name = read_server_name(body),
            EXT_ALPN => hello.alpn = read_alpn(body),
            EXT_SUPPORTED_VERSIONS => {
                if let Some(version) = highest_supported_version(body) {
                    hello.version = describe_version(version);
                }
            }
            _ => {}
        }
    }
}

fn read_server_name(body: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(body);
    let list_len = cursor.u16()? as usize;
    let mut list = Cursor::new(cursor.take(list_len)?);
    while let Some(name_type) = list.u8() {
        let name_len = list.u16()? as usize;
        let name = list.take(name_len)?;
        if name_type == SNI_HOST_NAME {
            return Some(escape_ascii(name));
        }
    }
    None
}

fn read_alpn(body: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = Cursor::new(body);
    let Some(list_len) = cursor.u16() else {
        return names;
    };
    let Some(list) = cursor.take(list_len as usize) else {
        return names;
    };
    let mut list = Cursor::new(list);
    while let Some(length) = list.u8() {
        let Some(protocol) = list.take(length as usize) else {
            break;
        };
        names.push(escape_ascii(protocol));
    }
    names
}

/// `supported_versions` in a ClientHello is a 1-byte-prefixed list of 2-byte
/// versions, most-preferred first. GREASE values are ignored.
fn highest_supported_version(body: &[u8]) -> Option<u16> {
    let mut cursor = Cursor::new(body);
    let list_len = cursor.u8()? as usize;
    let list = cursor.take(list_len)?;
    list.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .filter(|version| (0x0300..=0x0304).contains(version))
        .max()
}

fn escape_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            0x20..=0x7E => (*byte as char).to_string(),
            _ => format!("\\{byte:03}"),
        })
        .collect()
}

fn describe_version(version: u16) -> String {
    match version {
        0x0300 => "SSLv3".to_string(),
        0x0301 => "TLSv1.0".to_string(),
        0x0302 => "TLSv1.1".to_string(),
        0x0303 => "TLSv1.2".to_string(),
        0x0304 => "TLSv1.3".to_string(),
        other => format!("TLS 0x{other:04x}"),
    }
}

fn describe_content_type(content_type: u8) -> &'static str {
    match content_type {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        _ => "Unknown record",
    }
}

fn describe_handshake_type(handshake_type: u8) -> &'static str {
    match handshake_type {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

/// Minimal forward-only reader; every accessor returns `None` past the end so a
/// truncated or malformed record falls out of the parse instead of panicking.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let slice = self
            .bytes
            .get(self.offset..self.offset.checked_add(length)?)?;
        self.offset += length;
        Some(slice)
    }

    fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|slice| slice[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|slice| u16::from_be_bytes([slice[0], slice[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn server_name_extension(host: &str) -> Vec<u8> {
        let mut entry = vec![SNI_HOST_NAME];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host.as_bytes());

        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);
        extension(EXT_SERVER_NAME, &body)
    }

    fn alpn_extension(protocols: &[&str]) -> Vec<u8> {
        let mut list = Vec::new();
        for protocol in protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol.as_bytes());
        }
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        extension(EXT_ALPN, &body)
    }

    fn supported_versions_extension(versions: &[u16]) -> Vec<u8> {
        let mut list = Vec::new();
        for version in versions {
            list.extend_from_slice(&version.to_be_bytes());
        }
        let mut body = vec![list.len() as u8];
        body.extend_from_slice(&list);
        extension(EXT_SUPPORTED_VERSIONS, &body)
    }

    fn client_hello(legacy_version: u16, extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&legacy_version.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // empty session id
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1); // compression methods length
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(extensions);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let length = hello.len() as u32;
        handshake.extend_from_slice(&length.to_be_bytes()[1..]); // 24-bit length
        handshake.extend_from_slice(&hello);
        handshake
    }

    fn record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![content_type];
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn parses_a_tls13_client_hello() {
        let mut extensions = server_name_extension("example.com");
        extensions.extend_from_slice(&alpn_extension(&["h2", "http/1.1"]));
        extensions.extend_from_slice(&supported_versions_extension(&[0x0304, 0x0303]));
        let segment = record(
            CONTENT_TYPE_HANDSHAKE,
            0x0301,
            &client_hello(0x0303, &extensions),
        );

        let parsed = parse(&segment).expect("record parses");
        let hello = parsed.client_hello.as_ref().expect("client hello parses");

        assert_eq!(parsed.content_type, "Handshake");
        assert_eq!(parsed.handshake_type.as_deref(), Some("Client Hello"));
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(hello.version, "TLSv1.3");
        assert_eq!(describe(&parsed), "TLSv1.3 Client Hello (SNI=example.com)");
    }

    #[test]
    fn falls_back_to_the_legacy_version_without_supported_versions() {
        let segment = record(
            CONTENT_TYPE_HANDSHAKE,
            0x0301,
            &client_hello(0x0303, &server_name_extension("legacy.test")),
        );

        let parsed = parse(&segment).expect("record parses");

        assert_eq!(describe(&parsed), "TLSv1.2 Client Hello (SNI=legacy.test)");
    }

    #[test]
    fn parses_a_client_hello_with_no_extensions() {
        let segment = record(CONTENT_TYPE_HANDSHAKE, 0x0301, &client_hello(0x0303, &[]));

        let parsed = parse(&segment).expect("record parses");
        let hello = parsed.client_hello.as_ref().expect("client hello parses");

        assert!(hello.server_name.is_none());
        assert!(hello.alpn.is_empty());
        assert_eq!(describe(&parsed), "TLSv1.2 Client Hello");
    }

    #[test]
    fn describes_non_handshake_records() {
        let segment = record(23, 0x0303, &[0xAB; 16]);

        let parsed = parse(&segment).expect("record parses");

        assert!(parsed.client_hello.is_none());
        assert_eq!(describe(&parsed), "TLSv1.2 Application Data");
    }

    #[test]
    fn describes_other_handshake_messages() {
        let segment = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[2, 0, 0, 4, 3, 3, 0, 0]);

        let parsed = parse(&segment).expect("record parses");

        assert_eq!(describe(&parsed), "TLSv1.2 Server Hello");
    }

    #[test]
    fn survives_a_client_hello_cut_short_by_the_snaplen() {
        let mut segment = record(
            CONTENT_TYPE_HANDSHAKE,
            0x0301,
            &client_hello(0x0303, &server_name_extension("example.com")),
        );
        segment.truncate(segment.len() - 6);

        let parsed = parse(&segment).expect("record parses");

        // The SNI is gone with the bytes, but nothing panics and the record and
        // handshake type still decode.
        assert_eq!(parsed.handshake_type.as_deref(), Some("Client Hello"));
    }

    #[test]
    fn rejects_traffic_that_is_not_tls() {
        assert!(!looks_like_record(b"GET / HTTP/1.1\r\n"));
        assert!(parse(b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse(&[0x16, 0x03]).is_none());
    }
}
