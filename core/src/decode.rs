use crate::DecodedLayers;

const ARROW: &str = "\u{2192}";

pub fn build_summary_from_layers(layers: &DecodedLayers, default: String) -> String {
    if let Some(icmp) = &layers.icmp {
        if let Some(ipv4) = &layers.ipv4 {
            return format!(
                "{} {} {ARROW} {} ({})",
                icmp.version, ipv4.source, ipv4.destination, icmp.description
            );
        }
        if let Some(ipv6) = &layers.ipv6 {
            return format!(
                "{} {} {ARROW} {} ({})",
                icmp.version, ipv6.source, ipv6.destination, icmp.description
            );
        }
    }
    default
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodedLayers, IcmpHeader, Ipv4Header};
    #[test]
    fn icmp_summary_overrides_default() {
        let s = build_summary_from_layers(
            &DecodedLayers {
                icmp: Some(IcmpHeader {
                    icmp_type: 8,
                    icmp_code: 0,
                    description: "echo request".into(),
                    version: "ICMP".into(),
                }),
                ipv4: Some(Ipv4Header {
                    source: "1.1.1.1".into(),
                    destination: "2.2.2.2".into(),
                    protocol: 1,
                    header_length: 20,
                    total_length: 20,
                    ttl: 64,
                }),
                ..DecodedLayers::default()
            },
            "default".into(),
        );
        assert!(s.contains("echo request"));
    }
}
