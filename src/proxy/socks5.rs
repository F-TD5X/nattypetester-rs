use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{AppError, AppResult};
use crate::net::connect_tcp;

#[derive(Debug, Clone)]
pub struct Socks5ProxyConfig {
    pub endpoint: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5ProxyConfig {
    pub fn validate(&self) -> AppResult<()> {
        if self.username.is_none() && self.password.is_some() {
            return Err(AppError::InvalidInput(
                "SOCKS5 password requires SOCKS5 username".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn connect_via_proxy(
    proxy: &Socks5ProxyConfig,
    target: SocketAddr,
    timeout: Duration,
    local_bind: Option<SocketAddr>,
) -> AppResult<TcpStream> {
    proxy.validate()?;
    let mut stream = connect_tcp(proxy.endpoint, timeout, local_bind)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    negotiate_auth(&mut stream, proxy)?;
    let _proxy_bound = send_command(&mut stream, 0x01, target)?;
    Ok(stream)
}

pub fn udp_associate(
    proxy: &Socks5ProxyConfig,
    udp_local: SocketAddr,
    timeout: Duration,
    local_bind: Option<SocketAddr>,
) -> AppResult<(TcpStream, SocketAddr)> {
    proxy.validate()?;
    let mut stream = connect_tcp(proxy.endpoint, timeout, local_bind)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    negotiate_auth(&mut stream, proxy)?;
    let relay = send_command(&mut stream, 0x03, udp_local)?;
    Ok((stream, relay))
}

fn negotiate_auth(stream: &mut TcpStream, proxy: &Socks5ProxyConfig) -> AppResult<()> {
    let wants_password = proxy.username.is_some();
    let mut methods = vec![0x00_u8];
    if wants_password {
        methods.push(0x02);
    }

    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting)?;

    let mut response = [0_u8; 2];
    stream.read_exact(&mut response)?;
    if response[0] != 0x05 {
        return Err(AppError::Protocol(format!(
            "unexpected SOCKS5 auth version {}",
            response[0]
        )));
    }

    match response[1] {
        0x00 => Ok(()),
        0x02 => {
            let username = proxy.username.as_deref().ok_or_else(|| {
                AppError::Protocol("proxy requires username/password auth".to_string())
            })?;
            let password = proxy.password.as_deref().unwrap_or("");
            perform_username_password_auth(stream, username, password)
        }
        0xFF => Err(AppError::Protocol(
            "SOCKS5 proxy rejected all authentication methods".to_string(),
        )),
        method => Err(AppError::Protocol(format!(
            "unsupported SOCKS5 auth method: 0x{method:02x}"
        ))),
    }
}

fn perform_username_password_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> AppResult<()> {
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(AppError::InvalidInput(
            "SOCKS5 username/password must be <= 255 bytes".to_string(),
        ));
    }

    let mut packet = Vec::with_capacity(3 + username.len() + password.len());
    packet.push(0x01);
    packet.push(username.len() as u8);
    packet.extend_from_slice(username.as_bytes());
    packet.push(password.len() as u8);
    packet.extend_from_slice(password.as_bytes());
    stream.write_all(&packet)?;

    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x01 || reply[1] != 0x00 {
        return Err(AppError::Protocol(
            "SOCKS5 username/password authentication failed".to_string(),
        ));
    }
    Ok(())
}

fn send_command(stream: &mut TcpStream, command: u8, target: SocketAddr) -> AppResult<SocketAddr> {
    let mut request = Vec::with_capacity(22);
    request.push(0x05);
    request.push(command);
    request.push(0x00);
    write_socket_addr(&mut request, target);
    stream.write_all(&request)?;

    let mut head = [0_u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(AppError::Protocol(format!(
            "unexpected SOCKS5 command reply version {}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(AppError::Protocol(format!(
            "SOCKS5 command failed with code 0x{:02x}",
            head[1]
        )));
    }
    read_socket_addr(stream, head[3])
}

fn write_socket_addr(buffer: &mut Vec<u8>, address: SocketAddr) {
    match address {
        SocketAddr::V4(v4) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&v4.ip().octets());
            buffer.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buffer.push(0x04);
            buffer.extend_from_slice(&v6.ip().octets());
            buffer.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

fn read_socket_addr(stream: &mut TcpStream, atyp: u8) -> AppResult<SocketAddr> {
    match atyp {
        0x01 => {
            let mut buf = [0_u8; 6];
            stream.read_exact(&mut buf)?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut buf = [0_u8; 18];
            stream.read_exact(&mut buf)?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            let mut len_buf = [0_u8; 1];
            stream.read_exact(&mut len_buf)?;
            let name_len = len_buf[0] as usize;
            let mut buf = vec![0_u8; name_len + 2];
            stream.read_exact(&mut buf)?;
            let domain = String::from_utf8(buf[..name_len].to_vec()).map_err(|_| {
                AppError::Protocol("SOCKS5 returned non-UTF8 domain name".to_string())
            })?;
            let port = u16::from_be_bytes([buf[name_len], buf[name_len + 1]]);
            let resolved = (domain.as_str(), port)
                .to_socket_addrs()
                .map_err(|err| AppError::Resolve(format!("SOCKS5 domain {domain}:{port}: {err}")))?
                .next()
                .ok_or_else(|| AppError::Resolve(format!("SOCKS5 domain {domain}:{port}")))?
                .to_owned();
            Ok(resolved)
        }
        value => Err(AppError::Protocol(format!(
            "unsupported SOCKS5 address type 0x{value:02x}"
        ))),
    }
}

pub fn encode_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 22);
    packet.extend_from_slice(&[0, 0, 0]);
    write_socket_addr(&mut packet, target);
    packet.extend_from_slice(payload);
    packet
}

pub fn decode_udp_packet(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    let atyp = packet[3];
    let mut cursor = 4_usize;
    let source = match atyp {
        0x01 => {
            if packet.len() < cursor + 6 {
                return None;
            }
            let ip = Ipv4Addr::new(
                packet[cursor],
                packet[cursor + 1],
                packet[cursor + 2],
                packet[cursor + 3],
            );
            cursor += 4;
            let port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
            cursor += 2;
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if packet.len() < cursor + 18 {
                return None;
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[cursor..cursor + 16]);
            cursor += 16;
            let port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
            cursor += 2;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        _ => return None,
    };
    Some((source, &packet[cursor..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_udp_packet_roundtrip_ipv4() {
        let source = "203.0.113.5:3478".parse::<SocketAddr>().unwrap();
        let payload = b"hello-stun";
        let packet = encode_udp_packet(source, payload);
        let (decoded_source, decoded_payload) = decode_udp_packet(&packet).expect("decode");
        assert_eq!(decoded_source, source);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn decode_rejects_fragmented_packet() {
        let packet = [0_u8, 0_u8, 1_u8, 1, 127, 0, 0, 1, 0x0d, 0x96];
        assert!(decode_udp_packet(&packet).is_none());
    }
}
