use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sniffnet_packet_parser::LinkType;

/// IPFIX IE 61 `flowDirection` values: 0x00 = ingress, 0x01 = egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    Incoming = 0,
    Outgoing = 1,
}

pub fn get_direction(
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    my_interface_addresses: &[IpAddr],
) -> Option<FlowDirection> {
    if src_ip.is_loopback()
        && dst_ip.is_loopback()
        && let Some((sport, dport)) = src_port.zip(dst_port)
    {
        return Some(if sport > dport {
            FlowDirection::Outgoing
        } else {
            FlowDirection::Incoming
        });
    }

    if my_interface_addresses.is_empty() {
        return None;
    }

    let is_local = |ip: &IpAddr| my_interface_addresses.iter().any(|a| a == ip);

    Some(if is_local(src_ip) {
        FlowDirection::Outgoing
    } else if src_ip.ne(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        && src_ip.ne(&IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    {
        FlowDirection::Incoming
    } else if !is_local(dst_ip) {
        FlowDirection::Outgoing
    } else {
        FlowDirection::Incoming
    })
}

pub fn interface_addresses(interface_name: &str, link_type: LinkType) -> Vec<IpAddr> {
    let devices = match pcap::Device::list() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("failed to list interfaces while resolving '{interface_name}': {e}");
            return Vec::new();
        }
    };
    let is_sll = matches!(link_type, LinkType::LinuxSll(_) | LinkType::LinuxSll2(_));
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut matched = false;
    for dev in devices {
        if is_sll {
            addresses.extend(dev.addresses.into_iter().map(|a| a.addr));
        } else if dev.name == interface_name {
            addresses.extend(dev.addresses.into_iter().map(|a| a.addr));
            matched = true;
            break;
        }
    }
    if !is_sll && !matched {
        log::warn!("interface '{interface_name}' not found in device list");
    }
    if addresses.is_empty() {
        log::debug!("interface '{interface_name}' has no addresses");
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // The cases below mirror sniffnet's `traffic_direction_ipv4_test`.
    #[test]
    fn ipv4_matches_sniffnet_reference() {
        let my = vec![v4(172, 20, 10, 9)];

        assert_eq!(
            get_direction(
                &v4(172, 20, 10, 9),
                &v4(99, 88, 77, 0),
                Some(99),
                Some(99),
                &my
            ),
            Some(FlowDirection::Outgoing),
        );
        assert_eq!(
            get_direction(
                &v4(172, 20, 10, 10),
                &v4(172, 20, 10, 9),
                Some(99),
                Some(99),
                &my
            ),
            Some(FlowDirection::Incoming),
        );
        assert_eq!(
            get_direction(
                &v4(172, 20, 10, 9),
                &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                Some(99),
                Some(99),
                &my,
            ),
            Some(FlowDirection::Outgoing),
        );
        assert_eq!(
            get_direction(
                &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                &v4(172, 20, 10, 9),
                Some(99),
                Some(99),
                &my,
            ),
            Some(FlowDirection::Incoming),
        );
        assert_eq!(
            get_direction(
                &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                &v4(172, 20, 10, 10),
                Some(99),
                Some(99),
                &my,
            ),
            Some(FlowDirection::Outgoing),
        );
    }

    #[test]
    fn loopback_uses_port_ordering_without_interface_addresses() {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            get_direction(&lo, &lo, Some(40000), Some(443), &[]),
            Some(FlowDirection::Outgoing),
        );
        assert_eq!(
            get_direction(&lo, &lo, Some(443), Some(40000), &[]),
            Some(FlowDirection::Incoming),
        );
    }

    #[test]
    fn loopback_without_ports_falls_through() {
        // ICMP-like flow on loopback with no interface addresses — should be None,
        // not a guess.
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(get_direction(&lo, &lo, None, None, &[]), None);
    }

    #[test]
    fn none_when_interface_addresses_unknown() {
        // Non-loopback flow + empty interface addresses ⇒ no bogon guesswork.
        assert_eq!(
            get_direction(&v4(10, 0, 0, 1), &v4(8, 8, 8, 8), Some(1234), Some(53), &[]),
            None,
        );
    }
}
