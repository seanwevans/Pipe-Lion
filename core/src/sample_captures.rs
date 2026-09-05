//! The sample captures shipped with the web UI must stay parseable.
//!
//! They are the first thing a visitor opens, so a decoder change that breaks
//! one should fail here rather than on the deployed site. Regenerate them with
//! `python3 tools/make_sample_captures.py` if a format genuinely changes.
#![cfg(test)]

use crate::parse;

const DNS: &[u8] = include_bytes!("../../docs/public/samples/dns-lookup.pcap");
const TCP: &[u8] = include_bytes!("../../docs/public/samples/tcp-http.pcap");
const TLS: &[u8] = include_bytes!("../../docs/public/samples/tls-client-hello.pcap");
const ICMP: &[u8] = include_bytes!("../../docs/public/samples/icmp-ping.pcap");
const MIXED: &[u8] = include_bytes!("../../docs/public/samples/mixed-traffic.pcapng");

/// Every row's Info text, so assertions can look for a decoded detail.
fn summaries(bytes: &[u8]) -> Vec<String> {
    let handle = parse(bytes);
    assert!(
        handle.errors().is_empty(),
        "sample failed to parse: {:?}",
        handle.errors()
    );
    let json = handle.packets(0, handle.packet_count());
    let rows: serde_json::Value = serde_json::from_str(&json).expect("packet rows are JSON");
    rows.as_array()
        .expect("packet rows are an array")
        .iter()
        .map(|row| row["info"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn dns_sample_decodes_queries_and_responses() {
    let rows = summaries(DNS);
    assert_eq!(rows.len(), 3);
    assert!(rows[0].contains("Standard query"), "{}", rows[0]);
    assert!(rows[0].contains("A example.com"), "{}", rows[0]);
    assert!(rows[1].contains("response"), "{}", rows[1]);
    // mDNS: a PTR question on port 5353, name read through a compression-free walk.
    assert!(rows[2].contains("PTR _printer._tcp.local"), "{}", rows[2]);
}

#[test]
fn tcp_sample_covers_a_full_connection() {
    let rows = summaries(TCP);
    assert_eq!(rows.len(), 6, "handshake, request, response, and teardown");
    assert!(rows.iter().all(|row| row.starts_with("TCP ")), "{rows:?}");
}

#[test]
fn tls_sample_exposes_the_client_hello() {
    let rows = summaries(TLS);
    assert_eq!(rows.len(), 4);
    let hello = rows.last().expect("a final segment");
    assert!(hello.contains("Client Hello"), "{hello}");
    assert!(hello.contains("SNI=example.com"), "{hello}");
    assert!(hello.contains("TLSv1.3"), "{hello}");
}

#[test]
fn icmp_sample_covers_both_ip_versions() {
    let rows = summaries(ICMP);
    assert_eq!(rows.len(), 4);
    assert!(
        rows[0].contains("ICMP ") && rows[0].contains("echo request"),
        "{}",
        rows[0]
    );
    assert!(rows[1].contains("echo reply"), "{}", rows[1]);
    assert!(
        rows[2].contains("ICMPv6") && rows[2].contains("echo request"),
        "{}",
        rows[2]
    );
    assert!(
        rows[3].contains("ICMPv6") && rows[3].contains("echo reply"),
        "{}",
        rows[3]
    );
}

#[test]
fn mixed_sample_reads_as_pcapng() {
    let rows = summaries(MIXED);
    assert_eq!(rows.len(), 17, "every packet from the four pcap samples");
    assert!(rows.iter().any(|row| row.contains("A example.com")));
    assert!(rows.iter().any(|row| row.contains("SNI=example.com")));
    assert!(rows.iter().any(|row| row.contains("ICMPv6")));
}
