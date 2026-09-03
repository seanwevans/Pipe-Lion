//! Dispatch from a transport segment to an application-layer dissector.
//!
//! Both the IPv4 and IPv6 paths funnel through [`dissect`], so a dissector added
//! here works for either address family without further wiring.

use crate::dns;
use crate::models::DecodedLayers;
use crate::tls;

/// What an application dissector contributes to the packet row: the protocol
/// name for the Protocol column, and the Info text.
pub(crate) struct Dissection {
    pub(crate) protocol: &'static str,
    pub(crate) detail: String,
}

const TCP: u8 = 6;
const UDP: u8 = 17;
const UDP_HEADER_LEN: usize = 8;
const MIN_TCP_HEADER_LEN: usize = 20;

/// Length of the TCP header in `segment`, honouring the data-offset field.
pub(crate) fn tcp_header_length(segment: &[u8]) -> Option<usize> {
    let data_offset = ((*segment.get(12)? >> 4) as usize) * 4;
    (data_offset >= MIN_TCP_HEADER_LEN).then_some(data_offset)
}

/// The bytes above the transport header, or `None` when the header itself is
/// truncated (or the protocol has no payload we can locate).
fn payload(ip_protocol: u8, segment: &[u8]) -> Option<&[u8]> {
    match ip_protocol {
        TCP => segment.get(tcp_header_length(segment)?..),
        UDP => segment.get(UDP_HEADER_LEN..),
        _ => None,
    }
}

pub(crate) fn dissect(
    ip_protocol: u8,
    source_port: u16,
    destination_port: u16,
    segment: &[u8],
    layers: &mut DecodedLayers,
) -> Option<Dissection> {
    let payload = payload(ip_protocol, segment)?;
    if payload.is_empty() {
        return None;
    }

    if dns::is_dns_port(source_port) || dns::is_dns_port(destination_port) {
        // DNS over TCP prefixes the message with its 2-byte length.
        let message = if ip_protocol == TCP {
            payload.get(2..)?
        } else {
            payload
        };
        if let Some(header) = dns::parse(message) {
            let detail = dns::describe(&header);
            layers.dns = Some(header);
            return Some(Dissection {
                protocol: "DNS",
                detail,
            });
        }
    }

    if ip_protocol == TCP
        && let Some(record) = tls::parse(payload)
    {
        let detail = tls::describe(&record);
        layers.tls = Some(record);
        return Some(Dissection {
            protocol: "TLS",
            detail,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_segment(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut segment = source_port.to_be_bytes().to_vec();
        segment.extend_from_slice(&destination_port.to_be_bytes());
        segment.extend_from_slice(&((payload.len() + UDP_HEADER_LEN) as u16).to_be_bytes());
        segment.extend_from_slice(&0u16.to_be_bytes()); // checksum
        segment.extend_from_slice(payload);
        segment
    }

    fn tcp_segment(
        source_port: u16,
        destination_port: u16,
        header_words: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut segment = source_port.to_be_bytes().to_vec();
        segment.extend_from_slice(&destination_port.to_be_bytes());
        segment.extend_from_slice(&[0; 8]); // sequence, acknowledgement
        segment.push(header_words << 4);
        segment.push(0x18); // PSH, ACK
        segment.extend_from_slice(&[0; 6]); // window, checksum, urgent pointer
        let declared = (header_words as usize) * 4;
        if declared > segment.len() {
            segment.resize(declared, 0); // options padding
        }
        segment.extend_from_slice(payload);
        segment
    }

    fn dns_query() -> Vec<u8> {
        let mut message = vec![0x1A, 0x2B, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[7]);
        message.extend_from_slice(b"example");
        message.extend_from_slice(&[3]);
        message.extend_from_slice(b"com");
        message.push(0);
        message.extend_from_slice(&1u16.to_be_bytes()); // A
        message.extend_from_slice(&1u16.to_be_bytes()); // IN
        message
    }

    #[test]
    fn dissects_dns_over_udp() {
        let mut layers = DecodedLayers::default();
        let segment = udp_segment(51234, 53, &dns_query());

        let dissection = dissect(UDP, 51234, 53, &segment, &mut layers).expect("DNS is dissected");

        assert_eq!(dissection.protocol, "DNS");
        assert_eq!(dissection.detail, "Standard query 0x1a2b A example.com");
        assert!(layers.dns.is_some());
    }

    #[test]
    fn dissects_dns_over_tcp_past_the_length_prefix() {
        let query = dns_query();
        let mut payload = (query.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(&query);
        let segment = tcp_segment(51234, 53, 5, &payload);
        let mut layers = DecodedLayers::default();

        let dissection = dissect(TCP, 51234, 53, &segment, &mut layers).expect("DNS is dissected");

        assert_eq!(dissection.protocol, "DNS");
        assert_eq!(dissection.detail, "Standard query 0x1a2b A example.com");
    }

    #[test]
    fn honours_the_tcp_data_offset_when_options_are_present() {
        // A 32-byte header (8 words): the payload starts past 12 bytes of options.
        let segment = tcp_segment(443, 51234, 8, b"payload");

        assert_eq!(tcp_header_length(&segment), Some(32));
        assert_eq!(payload(TCP, &segment), Some(&b"payload"[..]));
    }

    #[test]
    fn rejects_a_data_offset_smaller_than_the_fixed_header() {
        let segment = tcp_segment(443, 51234, 3, b"payload");

        assert_eq!(tcp_header_length(&segment), None);
        assert_eq!(payload(TCP, &segment), None);
    }

    #[test]
    fn leaves_unrecognized_traffic_alone() {
        let segment = tcp_segment(51234, 8080, 5, b"GET / HTTP/1.1\r\n\r\n");
        let mut layers = DecodedLayers::default();

        assert!(dissect(TCP, 51234, 8080, &segment, &mut layers).is_none());
        assert!(layers.dns.is_none());
        assert!(layers.tls.is_none());
    }

    #[test]
    fn ignores_an_empty_payload() {
        let segment = tcp_segment(51234, 53, 5, b"");
        let mut layers = DecodedLayers::default();

        assert!(dissect(TCP, 51234, 53, &segment, &mut layers).is_none());
    }
}
