use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

pub fn interface_addresses(interface_name: &str) -> Vec<IpAddr> {
    let devices = match pcap::Device::list() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("failed to list interfaces while resolving '{interface_name}': {e}");
            return Vec::new();
        }
    };
    let Some(device) = devices.into_iter().find(|d| d.name == interface_name) else {
        log::warn!("interface '{interface_name}' not found in device list");
        return Vec::new();
    };
    let addrs: Vec<IpAddr> = device.addresses.into_iter().map(|a| a.addr).collect();
    if addrs.is_empty() {
        log::debug!("interface '{interface_name}' has no addresses");
    }
    addrs
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
