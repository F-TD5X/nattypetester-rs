use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::AppResult;
use crate::proxy::socks5::{
    Socks5ProxyConfig, decode_udp_packet, encode_udp_packet, udp_associate,
};

pub struct UdpDatagram {
    pub payload: Vec<u8>,
    pub remote: SocketAddr,
    pub local: SocketAddr,
}

pub enum UdpTransport {
    Direct(DirectUdpTransport),
    Socks5(Socks5UdpTransport),
}

impl UdpTransport {
    pub fn new(
        local_bind: SocketAddr,
        timeout: Duration,
        proxy: Option<Socks5ProxyConfig>,
    ) -> AppResult<Self> {
        match proxy {
            Some(proxy_cfg) => Ok(Self::Socks5(Socks5UdpTransport::new(
                local_bind, timeout, proxy_cfg,
            )?)),
            None => Ok(Self::Direct(DirectUdpTransport::new(local_bind, timeout)?)),
        }
    }

    pub fn request(
        &mut self,
        payload: &[u8],
        remote: SocketAddr,
        expected_remote: SocketAddr,
    ) -> AppResult<Option<UdpDatagram>> {
        match self {
            Self::Direct(inner) => inner.request(payload, remote, expected_remote),
            Self::Socks5(inner) => inner.request(payload, remote, expected_remote),
        }
    }

    pub fn socks5_relay_endpoint(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct(_) => None,
            Self::Socks5(inner) => Some(inner.relay),
        }
    }
}

pub struct DirectUdpTransport {
    socket: UdpSocket,
    timeout: Duration,
}

impl DirectUdpTransport {
    pub fn new(local_bind: SocketAddr, timeout: Duration) -> AppResult<Self> {
        let socket = UdpSocket::bind(local_bind)?;
        Ok(Self { socket, timeout })
    }

    pub fn request(
        &mut self,
        payload: &[u8],
        remote: SocketAddr,
        expected_remote: SocketAddr,
    ) -> AppResult<Option<UdpDatagram>> {
        self.socket.send_to(payload, remote)?;
        let mut buffer = vec![0_u8; 0x10000];
        let start = Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed >= self.timeout {
                return Ok(None);
            }
            self.socket
                .set_read_timeout(Some(self.timeout.saturating_sub(elapsed)))?;
            match self.socket.recv_from(&mut buffer) {
                Ok((received, source)) => {
                    if source != expected_remote {
                        continue;
                    }
                    let local = effective_local_endpoint(&self.socket, remote)?;
                    return Ok(Some(UdpDatagram {
                        payload: buffer[..received].to_vec(),
                        remote: source,
                        local,
                    }));
                }
                Err(error) if is_timeout(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

pub struct Socks5UdpTransport {
    socket: UdpSocket,
    relay: SocketAddr,
    _control: std::net::TcpStream,
    timeout: Duration,
}

impl Socks5UdpTransport {
    pub fn new(
        local_bind: SocketAddr,
        timeout: Duration,
        proxy: Socks5ProxyConfig,
    ) -> AppResult<Self> {
        let socket = UdpSocket::bind(local_bind)?;
        let associate_endpoint = advertise_udp_endpoint(&socket, proxy.endpoint)?;
        let control_local = Some(SocketAddr::new(associate_endpoint.ip(), 0));
        let (control, mut relay) =
            udp_associate(&proxy, associate_endpoint, timeout, control_local)?;
        if relay.ip().is_unspecified() {
            relay.set_ip(proxy.endpoint.ip());
        }
        Ok(Self {
            socket,
            relay,
            _control: control,
            timeout,
        })
    }

    pub fn request(
        &mut self,
        payload: &[u8],
        remote: SocketAddr,
        expected_remote: SocketAddr,
    ) -> AppResult<Option<UdpDatagram>> {
        let packet = encode_udp_packet(remote, payload);
        self.socket.send_to(&packet, self.relay)?;

        let mut buffer = vec![0_u8; 0x10000];
        let start = Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed >= self.timeout {
                return Ok(None);
            }
            self.socket
                .set_read_timeout(Some(self.timeout.saturating_sub(elapsed)))?;
            match self.socket.recv_from(&mut buffer) {
                Ok((received, source)) => {
                    if source != self.relay {
                        continue;
                    }
                    let (actual_source, data) = match decode_udp_packet(&buffer[..received]) {
                        Some(decoded) => decoded,
                        None => continue,
                    };
                    if actual_source != expected_remote {
                        continue;
                    }
                    let local = effective_local_endpoint(&self.socket, remote)?;
                    return Ok(Some(UdpDatagram {
                        payload: data.to_vec(),
                        remote: actual_source,
                        local,
                    }));
                }
                Err(error) if is_timeout(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn effective_local_endpoint(socket: &UdpSocket, remote: SocketAddr) -> AppResult<SocketAddr> {
    let local = socket.local_addr()?;
    if !local.ip().is_unspecified() {
        return Ok(local);
    }

    let probe_bind = if remote.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let probe = UdpSocket::bind(probe_bind)?;
    probe.connect(remote)?;
    let resolved = probe.local_addr()?;
    Ok(SocketAddr::new(resolved.ip(), local.port()))
}

fn advertise_udp_endpoint(socket: &UdpSocket, proxy_endpoint: SocketAddr) -> AppResult<SocketAddr> {
    let local = socket.local_addr()?;
    if !local.ip().is_unspecified() {
        return Ok(local);
    }

    let probe_bind = if proxy_endpoint.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let probe = UdpSocket::bind(probe_bind)?;
    probe.connect(proxy_endpoint)?;
    let concrete = probe.local_addr()?;
    Ok(SocketAddr::new(concrete.ip(), local.port()))
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
