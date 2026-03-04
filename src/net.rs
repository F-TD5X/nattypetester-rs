use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamilyHint {
    V4,
    V6,
}

impl IpFamilyHint {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        if addr.is_ipv4() { Self::V4 } else { Self::V6 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: Option<u16>,
}

impl HostPort {
    pub fn with_default_port(&self, default_port: u16) -> u16 {
        self.port.unwrap_or(default_port)
    }

    pub fn with_port_string(&self, port: u16) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{port}", self.host)
        } else {
            format!("{}:{port}", self.host)
        }
    }

    pub fn is_ip_literal(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok()
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}", self.with_port_string(port)),
            None => write!(f, "{}", self.host),
        }
    }
}

impl FromStr for HostPort {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let value = raw.trim();
        if value.is_empty() {
            return Err("endpoint cannot be empty".to_string());
        }

        if let Ok(parsed) = value.parse::<SocketAddr>() {
            return Ok(Self {
                host: parsed.ip().to_string(),
                port: Some(parsed.port()),
            });
        }

        if value.starts_with('[') {
            let close = value
                .find(']')
                .ok_or_else(|| "missing closing bracket for IPv6 address".to_string())?;
            let host = &value[1..close];
            if host.is_empty() {
                return Err("host cannot be empty".to_string());
            }
            let rest = &value[close + 1..];
            if rest.is_empty() {
                return Ok(Self {
                    host: host.to_string(),
                    port: None,
                });
            }
            if !rest.starts_with(':') {
                return Err("invalid bracketed endpoint format".to_string());
            }
            let port: u16 = rest[1..]
                .parse()
                .map_err(|_| "invalid port number".to_string())?;
            return Ok(Self {
                host: host.to_string(),
                port: Some(port),
            });
        }

        if let Some((host, port_raw)) = value.rsplit_once(':')
            && !host.contains(':')
            && port_raw.chars().all(|ch| ch.is_ascii_digit())
        {
            let port: u16 = port_raw
                .parse()
                .map_err(|_| "invalid port number".to_string())?;
            if host.is_empty() {
                return Err("host cannot be empty".to_string());
            }
            return Ok(Self {
                host: host.to_string(),
                port: Some(port),
            });
        }

        Ok(Self {
            host: value.to_string(),
            port: None,
        })
    }
}

pub fn resolve_host_port(
    endpoint: &HostPort,
    default_port: u16,
    family_hint: Option<IpFamilyHint>,
) -> AppResult<(SocketAddr, String)> {
    let port = endpoint.with_default_port(default_port);
    let display = endpoint.with_port_string(port);

    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        if let Some(hint) = family_hint {
            match (hint, ip) {
                (IpFamilyHint::V4, IpAddr::V4(_)) | (IpFamilyHint::V6, IpAddr::V6(_)) => {}
                (IpFamilyHint::V4, IpAddr::V6(_)) => {
                    return Err(AppError::InvalidInput(format!(
                        "endpoint {} is IPv6 but -4 was selected",
                        endpoint.host
                    )));
                }
                (IpFamilyHint::V6, IpAddr::V4(_)) => {
                    return Err(AppError::InvalidInput(format!(
                        "endpoint {} is IPv4 but -6 was selected",
                        endpoint.host
                    )));
                }
            }
        }
        return Ok((SocketAddr::new(ip, port), display));
    }

    let mut resolved = (endpoint.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|err| AppError::Resolve(format!("{display}: {err}")))?;

    let mut first: Option<SocketAddr> = None;
    let mut matched: Option<SocketAddr> = None;
    for addr in &mut resolved {
        if first.is_none() {
            first = Some(addr);
        }
        match family_hint {
            Some(IpFamilyHint::V4) if addr.is_ipv4() => {
                matched = Some(addr);
                break;
            }
            Some(IpFamilyHint::V6) if addr.is_ipv6() => {
                matched = Some(addr);
                break;
            }
            None => {
                matched = Some(addr);
                break;
            }
            _ => {}
        }
    }

    let addr = match family_hint {
        Some(IpFamilyHint::V4) => matched.ok_or_else(|| {
            AppError::Resolve(format!(
                "no IPv4 address records for endpoint {}",
                endpoint.host
            ))
        })?,
        Some(IpFamilyHint::V6) => matched.ok_or_else(|| {
            AppError::Resolve(format!(
                "no IPv6 address records for endpoint {}",
                endpoint.host
            ))
        })?,
        None => first.ok_or_else(|| {
            AppError::Resolve(format!("no address records for endpoint {}", endpoint.host))
        })?,
    };

    Ok((addr, display))
}

pub fn default_local_endpoint(family_hint: IpFamilyHint) -> SocketAddr {
    match family_hint {
        IpFamilyHint::V4 => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpFamilyHint::V6 => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    }
}

pub fn ensure_local_family(remote: SocketAddr, local: SocketAddr) -> AppResult<()> {
    if remote.is_ipv4() == local.is_ipv4() {
        return Ok(());
    }
    Err(AppError::InvalidInput(format!(
        "local endpoint family {} does not match server family {}",
        if local.is_ipv4() { "IPv4" } else { "IPv6" },
        if remote.is_ipv4() { "IPv4" } else { "IPv6" }
    )))
}

pub fn connect_tcp(
    remote: SocketAddr,
    timeout: Duration,
    local_bind: Option<SocketAddr>,
) -> io::Result<TcpStream> {
    match attempt_connect(remote, timeout, local_bind) {
        Ok(stream) => Ok(stream),
        Err(err)
            if should_fallback_local_bind(local_bind, &err)
                && local_bind.map(|addr| addr.port() != 0).unwrap_or(false) =>
        {
            let fallback = local_bind.map(|addr| SocketAddr::new(addr.ip(), 0));
            attempt_connect(remote, timeout, fallback)
        }
        Err(err) => Err(err),
    }
}

fn should_fallback_local_bind(local_bind: Option<SocketAddr>, err: &io::Error) -> bool {
    local_bind.is_some()
        && matches!(
            err.kind(),
            io::ErrorKind::AddrInUse
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::PermissionDenied
        )
}

fn attempt_connect(
    remote: SocketAddr,
    timeout: Duration,
    local_bind: Option<SocketAddr>,
) -> io::Result<TcpStream> {
    let domain = Domain::for_address(remote);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    if let Some(local) = local_bind {
        socket.bind(&SockAddr::from(local))?;
    }
    socket.connect_timeout(&SockAddr::from(remote), timeout)?;
    let stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_literal_ipv4_with_ipv4_hint() {
        let host = "203.0.113.7".parse::<HostPort>().unwrap();
        let (resolved, display) = resolve_host_port(&host, 3478, Some(IpFamilyHint::V4)).unwrap();
        assert_eq!(resolved, "203.0.113.7:3478".parse().unwrap());
        assert_eq!(display, "203.0.113.7:3478");
    }

    #[test]
    fn resolve_literal_ipv4_rejects_ipv6_hint() {
        let host = "203.0.113.7".parse::<HostPort>().unwrap();
        let error = resolve_host_port(&host, 3478, Some(IpFamilyHint::V6)).unwrap_err();
        assert!(error.to_string().contains("IPv4"));
    }

    #[test]
    fn resolve_literal_ipv6_rejects_ipv4_hint() {
        let host = "2001:db8::1".parse::<HostPort>().unwrap();
        let error = resolve_host_port(&host, 3478, Some(IpFamilyHint::V4)).unwrap_err();
        assert!(error.to_string().contains("IPv6"));
    }
}
