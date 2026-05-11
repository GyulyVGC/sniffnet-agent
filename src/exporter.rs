use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::flow::{FlowKey, FlowSnapshot};
use crate::ipfix::encode::build_datagrams;

pub struct Exporter {
    sock: UdpSocket,
    seq: u32,
    last_template_send: Option<Instant>,
    template_refresh: Duration,
    odid: u32,
    mtu: usize,
}

impl Exporter {
    pub fn connect(
        addr: SocketAddr,
        odid: u32,
        template_refresh: Duration,
        mtu: usize,
    ) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let sock = UdpSocket::bind(bind_addr)?;
        sock.connect(addr)?;
        Ok(Self {
            sock,
            seq: 0,
            last_template_send: None,
            template_refresh,
            odid,
            mtu,
        })
    }

    pub fn flush(&mut self, snapshots: Vec<(FlowKey, FlowSnapshot)>) -> io::Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let include_template_set = match self.last_template_send {
            None => true,
            Some(t) => t.elapsed() >= self.template_refresh,
        };
        let now_unix = unix_seconds();
        let (datagrams, new_seq) = build_datagrams(
            &snapshots,
            self.odid,
            self.seq,
            self.mtu,
            include_template_set,
            now_unix,
        );
        if include_template_set {
            self.last_template_send = Some(Instant::now());
        }
        // Advance the sequence number unconditionally — RFC 7011 lets the collector
        // detect loss via the gap, and this matches standard exporter behavior.
        self.seq = new_seq;

        let mut last_err: Option<io::Error> = None;
        for dg in &datagrams {
            if let Err(e) = self.sock.send(dg) {
                warn!("UDP send failed: {e}");
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
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(a: u8) -> (FlowKey, FlowSnapshot) {
        (
            FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                src_port: 1000 + u16::from(a),
                dst_port: 443,
                protocol: 6,
            },
            FlowSnapshot {
                bytes: 100,
                packets: 1,
                src_mac: [0; 6],
                dst_mac: [0; 6],
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

        let mut exp = Exporter::connect(recv_addr, 7, Duration::from_secs(60), 1400).unwrap();
        exp.flush(vec![flow(1)]).unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = recv.recv_from(&mut buf).unwrap();
        // first datagram: header(16) + template set(84) + data set(4 + 41) = 145
        assert_eq!(n, 145);
        // set after header should be the Template Set (id=2)
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 2);

        exp.flush(vec![flow(2)]).unwrap();
        let (n2, _) = recv.recv_from(&mut buf).unwrap();
        // second datagram should NOT include templates: 16 + 4 + 41 = 61
        assert_eq!(n2, 61);
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 256);
    }

    #[test]
    fn flush_with_empty_snapshots_is_noop_and_no_socket_write() {
        // Bind a receiver that we'll assert never gets data.
        let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
        recv.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut exp =
            Exporter::connect(recv.local_addr().unwrap(), 1, Duration::from_secs(60), 1400)
                .unwrap();
        exp.flush(vec![]).unwrap();
        let mut buf = [0u8; 64];
        assert!(recv.recv_from(&mut buf).is_err(), "no datagram expected");
    }
}
