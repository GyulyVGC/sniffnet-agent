use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::flow::{FlowKey, FlowVal};
use crate::ipfix::encode::build_datagrams;

pub struct Exporter {
    sock: UdpSocket,
    seq: u32,
    odid: u32,
    last_template_send: Option<Instant>,
}

impl Exporter {
    pub fn connect(addr: SocketAddr, odid: u32) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let sock = UdpSocket::bind(bind_addr)?;
        sock.connect(addr)?;
        Ok(Self {
            sock,
            seq: 0,
            odid,
            last_template_send: None,
        })
    }

    pub fn flush(&mut self, flows: &[(FlowKey, FlowVal)]) -> io::Result<()> {
        if flows.is_empty() {
            return Ok(());
        }
        let include_template_set = match self.last_template_send {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(30),
        };
        let now_unix = unix_seconds();
        let (datagrams, new_seq) =
            build_datagrams(flows, self.seq, include_template_set, now_unix, self.odid);
        if include_template_set {
            self.last_template_send = Some(Instant::now());
        }
        // Advance the sequence number unconditionally — RFC 7011 lets the collector
        // detect loss via the gap, and this matches standard exporter behavior.
        self.seq = new_seq;

        let mut last_err: Option<io::Error> = None;
        for dg in &datagrams {
            if let Err(e) = self.sock.send(dg) {
                log::debug!("UDP send failed ({} bytes): {e}", dg.len());
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowAddrs, FlowKey};
    use sniffnet_packet_parser::Protocol;
    use std::net::Ipv4Addr;

    fn flow(a: u8) -> (FlowKey, FlowVal) {
        (
            FlowKey {
                addrs: FlowAddrs::V4 {
                    src: Ipv4Addr::new(10, 0, 0, a),
                    dst: Ipv4Addr::new(10, 0, 0, 99),
                },
                src_port: Some(1000 + u16::from(a)),
                dst_port: Some(443),
                protocol: Protocol::Tcp,
            },
            FlowVal {
                bytes: 100,
                packets: 1,
                src_mac: None,
                dst_mac: None,
                vlan_id: None,
                ether_type: 0x0800,
                direction: None,
                first_seen_ms: 0,
                last_seen_ms: 0,
            },
        )
    }

    /// Bind a receiver to a free port, point the exporter at it, then read the
    /// resulting datagrams off the socket and assert the high-level shape.
    #[test]
    fn round_trip_first_flush_carries_template_then_subsequent_does_not() {
        let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
        recv.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let recv_addr = recv.local_addr().unwrap();

        let mut exp = Exporter::connect(recv_addr, 0).unwrap();
        exp.flush(&vec![flow(1)]).unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = recv.recv_from(&mut buf).unwrap();
        // first datagram: header(16) + template set(124) + data set(4 + 62) = 206
        assert_eq!(n, 206);
        // set after header should be the Template Set (id=2)
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 2);

        exp.flush(&vec![flow(2)]).unwrap();
        let (n2, _) = recv.recv_from(&mut buf).unwrap();
        // second datagram should NOT include templates: 16 + 4 + 62 = 82
        assert_eq!(n2, 82);
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 256);
    }

    #[test]
    fn flush_with_empty_flows_is_noop_and_no_socket_write() {
        // Bind a receiver that we'll assert never gets data.
        let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
        recv.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut exp = Exporter::connect(recv.local_addr().unwrap(), 0).unwrap();
        exp.flush(&vec![]).unwrap();
        let mut buf = [0u8; 64];
        assert!(recv.recv_from(&mut buf).is_err(), "no datagram expected");
    }
}
