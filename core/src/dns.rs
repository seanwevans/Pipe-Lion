//! DNS dissection: header flags plus the question section.
//!
//! Answer records are deliberately not decoded — the question is what the Info
//! column and display filters actually key on, and skipping the RDATA parsers
//! keeps this module free of per-record-type special cases.

use crate::models::{DnsHeader, DnsQuestion};

const HEADER_LEN: usize = 12;
const MAX_QUESTIONS: usize = 8;
/// Bound on compression-pointer jumps while reading one name. A name cannot
/// legitimately need more than a handful, and a cap is what stops a message
/// whose pointers form a cycle from hanging the parser.
const MAX_POINTER_JUMPS: usize = 16;

/// UDP/TCP ports that carry DNS wire format: classic DNS and mDNS.
pub(crate) fn is_dns_port(port: u16) -> bool {
    matches!(port, 53 | 5353)
}

pub(crate) fn parse(message: &[u8]) -> Option<DnsHeader> {
    if message.len() < HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let question_count = u16::from_be_bytes([message[4], message[5]]);
    let answer_count = u16::from_be_bytes([message[6], message[7]]);
    let authority_count = u16::from_be_bytes([message[8], message[9]]);
    let additional_count = u16::from_be_bytes([message[10], message[11]]);

    let is_response = flags & 0x8000 != 0;
    let opcode = describe_opcode(((flags >> 11) & 0x0F) as u8);
    let rcode = describe_rcode((flags & 0x0F) as u8);
    let truncated = flags & 0x0200 != 0;

    let mut questions = Vec::new();
    let mut offset = HEADER_LEN;
    for _ in 0..question_count.min(MAX_QUESTIONS as u16) {
        // A malformed or truncated question stops the walk; the header we
        // already read is still worth reporting.
        let Some((name, next)) = read_name(message, offset) else {
            break;
        };
        if next + 4 > message.len() {
            break;
        }
        let qtype = u16::from_be_bytes([message[next], message[next + 1]]);
        let qclass = u16::from_be_bytes([message[next + 2], message[next + 3]]);
        questions.push(DnsQuestion {
            name,
            qtype: describe_qtype(qtype).to_string(),
            // mDNS reuses the top class bit as the "unicast response" flag.
            qclass: describe_qclass(qclass & 0x7FFF).to_string(),
        });
        offset = next + 4;
    }

    Some(DnsHeader {
        id,
        is_response,
        truncated,
        opcode: opcode.to_string(),
        rcode: rcode.to_string(),
        question_count,
        answer_count,
        authority_count,
        additional_count,
        questions,
    })
}

/// Wireshark-style Info text, e.g. `Standard query 0x1a2b A example.com`.
pub(crate) fn describe(header: &DnsHeader) -> String {
    let mut text = header.opcode.clone();
    if header.is_response {
        text.push_str(" response");
    }
    text.push_str(&format!(" 0x{:04x}", header.id));

    if let Some(question) = header.questions.first() {
        text.push_str(&format!(" {} {}", question.qtype, question.name));
    }
    if header.is_response && header.rcode != "No error" {
        text.push_str(&format!(" ({})", header.rcode));
    }
    if header.truncated {
        text.push_str(" [truncated]");
    }
    text
}

/// Reads a (possibly compressed) domain name, returning it alongside the offset
/// just past the name *in the record* — following a pointer never advances the
/// caller's cursor beyond the two pointer bytes.
fn read_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut end_of_record: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let length = *message.get(offset)? as usize;

        if length & 0xC0 == 0xC0 {
            let low = *message.get(offset + 1)? as usize;
            let target = ((length & 0x3F) << 8) | low;
            end_of_record.get_or_insert(offset + 2);
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS || target >= message.len() {
                return None;
            }
            offset = target;
            continue;
        }

        if length & 0xC0 != 0 {
            // Reserved label type (0b01/0b10); nothing sane follows.
            return None;
        }

        offset += 1;
        if length == 0 {
            break;
        }

        let label = message.get(offset..offset + length)?;
        labels.push(escape_label(label));
        offset += length;
    }

    let name = if labels.is_empty() {
        "<root>".to_string()
    } else {
        labels.join(".")
    };
    Some((name, end_of_record.unwrap_or(offset)))
}

/// Labels are arbitrary bytes on the wire. Render the printable ASCII subset
/// literally and escape everything else, so a hostile name cannot smuggle
/// control characters into the Info column.
fn escape_label(label: &[u8]) -> String {
    let mut text = String::with_capacity(label.len());
    for byte in label {
        match byte {
            0x20..=0x2D | 0x2F..=0x7E => text.push(*byte as char),
            _ => text.push_str(&format!("\\{byte:03}")),
        }
    }
    text
}

fn describe_opcode(opcode: u8) -> &'static str {
    match opcode {
        0 => "Standard query",
        1 => "Inverse query",
        2 => "Server status request",
        4 => "Notify",
        5 => "Update",
        _ => "Unknown opcode",
    }
}

fn describe_rcode(rcode: u8) -> &'static str {
    match rcode {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "Non-existent domain",
        4 => "Not implemented",
        5 => "Refused",
        6 => "Name exists when it should not",
        9 => "Not authoritative",
        10 => "Name not contained in zone",
        _ => "Unknown response code",
    }
}

fn describe_qtype(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => "TYPE",
    }
}

fn describe_qclass(qclass: u16) -> &'static str {
    match qclass {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "ANY",
        _ => "CLASS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn message(id: u16, flags: u16, counts: [u16; 4], tail: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes.extend_from_slice(tail);
        bytes
    }

    fn question(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut bytes = labels(name);
        bytes.extend_from_slice(&qtype.to_be_bytes());
        bytes.extend_from_slice(&qclass.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_a_standard_query() {
        let data = message(0x1A2B, 0x0100, [1, 0, 0, 0], &question("example.com", 1, 1));

        let header = parse(&data).expect("query parses");

        assert_eq!(header.id, 0x1A2B);
        assert!(!header.is_response);
        assert_eq!(header.opcode, "Standard query");
        assert_eq!(header.question_count, 1);
        assert_eq!(header.questions.len(), 1);
        assert_eq!(header.questions[0].name, "example.com");
        assert_eq!(header.questions[0].qtype, "A");
        assert_eq!(header.questions[0].qclass, "IN");
        assert_eq!(describe(&header), "Standard query 0x1a2b A example.com");
    }

    #[test]
    fn parses_a_response_and_reports_the_response_code() {
        let data = message(
            0x0007,
            0x8183, // response, recursion desired/available, NXDOMAIN
            [1, 0, 1, 0],
            &question("nope.example", 28, 1),
        );

        let header = parse(&data).expect("response parses");

        assert!(header.is_response);
        assert_eq!(header.rcode, "Non-existent domain");
        assert_eq!(
            describe(&header),
            "Standard query response 0x0007 AAAA nope.example (Non-existent domain)"
        );
    }

    #[test]
    fn follows_compression_pointers() {
        // Two questions; the second reuses the first name via a pointer to 0x0c.
        let mut tail = question("example.com", 1, 1);
        tail.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        tail.extend_from_slice(&28u16.to_be_bytes());
        tail.extend_from_slice(&1u16.to_be_bytes());
        let data = message(1, 0x0100, [2, 0, 0, 0], &tail);

        let header = parse(&data).expect("query parses");

        assert_eq!(header.questions.len(), 2);
        assert_eq!(header.questions[1].name, "example.com");
        assert_eq!(header.questions[1].qtype, "AAAA");
    }

    #[test]
    fn rejects_a_pointer_loop_instead_of_hanging() {
        // A name at offset 12 that points at itself.
        let data = message(
            1,
            0x0100,
            [1, 0, 0, 0],
            &[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01],
        );

        let header = parse(&data).expect("header still parses");

        assert!(header.questions.is_empty());
    }

    #[test]
    fn escapes_non_printable_bytes_in_names() {
        let mut tail = vec![3, b'a', 0x00, b'b', 0];
        tail.extend_from_slice(&1u16.to_be_bytes());
        tail.extend_from_slice(&1u16.to_be_bytes());
        let data = message(1, 0x0100, [1, 0, 0, 0], &tail);

        let header = parse(&data).expect("query parses");

        assert_eq!(header.questions[0].name, "a\\000b");
    }

    #[test]
    fn treats_mdns_unicast_response_bit_as_class_in() {
        let data = message(
            1,
            0x0000,
            [1, 0, 0, 0],
            &question("_http._tcp.local", 12, 0x8001),
        );

        let header = parse(&data).expect("query parses");

        assert_eq!(header.questions[0].qclass, "IN");
    }

    #[test]
    fn rejects_a_message_shorter_than_the_header() {
        assert!(parse(&[0u8; 11]).is_none());
    }

    #[test]
    fn recognizes_dns_ports() {
        assert!(is_dns_port(53));
        assert!(is_dns_port(5353));
        assert!(!is_dns_port(443));
    }
}
