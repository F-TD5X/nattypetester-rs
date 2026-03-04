use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::error::{AppError, AppResult};
use crate::net::connect_tcp;
use crate::proxy::socks5::{Socks5ProxyConfig, connect_via_proxy};

pub struct StreamResponse {
    pub payload: Vec<u8>,
    pub local: SocketAddr,
}

pub fn request_stun_over_stream(
    payload: &[u8],
    remote: SocketAddr,
    timeout: Duration,
    local_bind: SocketAddr,
    proxy: Option<&Socks5ProxyConfig>,
    use_tls: bool,
    tls_server_name: Option<&str>,
) -> AppResult<Option<StreamResponse>> {
    let mut stream = match proxy {
        Some(proxy_cfg) => connect_via_proxy(proxy_cfg, remote, timeout, Some(local_bind))?,
        None => connect_tcp(remote, timeout, Some(local_bind))?,
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    if use_tls {
        let server_name = tls_server_name.ok_or_else(|| {
            AppError::InvalidInput(
                "TLS transport requires --sni for IP literal servers".to_string(),
            )
        })?;
        let local = stream.local_addr()?;
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_name.to_string()).map_err(|_| {
            AppError::InvalidInput("TLS transport requires a valid DNS name in --sni".to_string())
        })?;
        let connection = ClientConnection::new(Arc::new(config), server_name)?;
        let mut tls_stream = StreamOwned::new(connection, stream);
        tls_stream.write_all(payload)?;
        tls_stream.flush()?;
        let response = read_single_stun_message(&mut tls_stream)?;
        Ok(response.map(|raw| StreamResponse {
            payload: raw,
            local,
        }))
    } else {
        let local = stream.local_addr()?;
        stream.write_all(payload)?;
        stream.flush()?;
        let response = read_single_stun_message(&mut stream)?;
        Ok(response.map(|raw| StreamResponse {
            payload: raw,
            local,
        }))
    }
}

fn read_single_stun_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 20];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if is_soft_read_end(&error) => return Ok(None),
        Err(error) => return Err(error),
    }

    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0_u8; payload_len];
    match reader.read_exact(&mut payload) {
        Ok(()) => {}
        Err(error) if is_soft_read_end(&error) => return Ok(None),
        Err(error) => return Err(error),
    }

    let mut frame = Vec::with_capacity(20 + payload_len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    Ok(Some(frame))
}

fn is_soft_read_end(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::UnexpectedEof
    )
}
