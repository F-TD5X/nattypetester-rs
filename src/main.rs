use clap::Parser;
use nattypetester::cli::{Cli, ResolvedCli};
use nattypetester::defaults::{DEFAULT_STUN_PORT, DEFAULT_STUN_TLS_PORT, default_server};
use nattypetester::error::{AppError, AppResult};
use nattypetester::model::{
    BindingTestResult, ExecutionReport, FilteringBehavior, RunMode, TransportType,
};
use nattypetester::net::{
    HostPort, IpFamilyHint, default_local_endpoint, ensure_local_family, resolve_host_port,
};
use nattypetester::output::{render_json, render_text};
use nattypetester::proxy::socks5::Socks5ProxyConfig;
use nattypetester::rfc3489::run_rfc3489;
use nattypetester::rfc5780::{run_stream, run_udp};
use nattypetester::transport::udp::UdpTransport;

fn main() {
    let resolved = Cli::parse().resolve();
    let requested_transport: TransportType = resolved.options.transport.into();
    let fallback_server = resolved
        .options
        .server
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| default_server().to_string());

    let result = execute(&resolved);
    match result {
        Ok(report) => {
            emit_report(&resolved, &report);
        }
        Err(error) => {
            let mut failure = ExecutionReport::failed(
                resolved.mode,
                resolved.mode,
                requested_transport,
                fallback_server,
                error.to_string(),
            );
            let (proxy_type, proxy_server) = selected_proxy_summary(&resolved.options);
            failure.proxy_type = proxy_type;
            failure.proxy_server = proxy_server;
            emit_report(&resolved, &failure);
            std::process::exit(1);
        }
    }
}

fn emit_report(resolved: &ResolvedCli, report: &ExecutionReport) {
    if resolved.options.json {
        match render_json(report) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("failed to render JSON output: {err}");
                std::process::exit(1);
            }
        }
    } else {
        println!("{}", render_text(report));
    }
}

fn execute(resolved: &ResolvedCli) -> AppResult<ExecutionReport> {
    let mode = resolved.mode;
    let options = &resolved.options;
    let transport: TransportType = options.transport.into();

    if mode == RunMode::Rfc3489 && transport != TransportType::Udp {
        return Err(AppError::InvalidInput(
            "RFC3489 mode supports only UDP transport".to_string(),
        ));
    }
    if options.socks_pass.is_some() && options.socks_user.is_none() {
        return Err(AppError::InvalidInput(
            "--socks-pass requires --socks-user".to_string(),
        ));
    }

    let server_endpoint = options.server.clone().unwrap_or_else(|| {
        default_server()
            .parse::<HostPort>()
            .expect("default server is valid")
    });

    let default_port = if transport == TransportType::Tls {
        DEFAULT_STUN_TLS_PORT
    } else {
        DEFAULT_STUN_PORT
    };

    let explicit_family = match (options.ipv4, options.ipv6) {
        (true, false) => Some(IpFamilyHint::V4),
        (false, true) => Some(IpFamilyHint::V6),
        _ => None,
    };
    if let (Some(local), Some(family)) = (options.local_endpoint, explicit_family)
        && IpFamilyHint::from_socket_addr(local) != family
    {
        return Err(AppError::InvalidInput(
            "--local-endpoint family does not match -4/-6 selection".to_string(),
        ));
    }
    let family_hint =
        explicit_family.or_else(|| options.local_endpoint.map(IpFamilyHint::from_socket_addr));
    let (server_addr, server_display) =
        resolve_host_port(&server_endpoint, default_port, family_hint)?;

    let local_bind = options.local_endpoint.unwrap_or_else(|| {
        let family = IpFamilyHint::from_socket_addr(server_addr);
        default_local_endpoint(family)
    });
    ensure_local_family(server_addr, local_bind)?;

    let proxy = build_proxy_config(options, local_bind)?;

    let mut tls_server_name = options.sni.clone();
    if transport == TransportType::Tls && tls_server_name.is_none() {
        if server_endpoint.is_ip_literal() {
            return Err(AppError::InvalidInput(
                "TLS with IP literal server requires --sni".to_string(),
            ));
        }
        tls_server_name = Some(server_endpoint.host.clone());
    }

    match transport {
        TransportType::Udp => execute_udp(
            mode,
            server_display,
            server_addr,
            options.timeout,
            local_bind,
            proxy,
            transport,
        ),
        TransportType::Tcp | TransportType::Tls => execute_stream(
            mode,
            server_display,
            server_addr,
            options.timeout,
            local_bind,
            proxy.as_ref(),
            transport,
            tls_server_name.as_deref(),
        ),
    }
}

fn execute_udp(
    mode: RunMode,
    server_display: String,
    server_addr: std::net::SocketAddr,
    timeout: std::time::Duration,
    local_bind: std::net::SocketAddr,
    proxy: Option<Socks5ProxyConfig>,
    transport: TransportType,
) -> AppResult<ExecutionReport> {
    let proxy_server = proxy.as_ref().map(|cfg| cfg.endpoint.to_string());
    let proxy_type = proxy.as_ref().map(|_| "socks5".to_string());
    let mut udp = UdpTransport::new(local_bind, timeout, proxy)?;
    let proxy_udp_relay = udp.socks5_relay_endpoint();
    match mode {
        RunMode::Rfc3489 => {
            let classic = run_rfc3489(&mut udp, server_addr)?;
            Ok(ExecutionReport {
                requested_mode: mode,
                effective_mode: RunMode::Rfc3489,
                transport,
                server: server_display,
                proxy_type: proxy_type.clone(),
                proxy_server: proxy_server.clone(),
                proxy_udp_relay,
                classic_result: Some(classic),
                modern_result: None,
                error: None,
            })
        }
        RunMode::Rfc5780 | RunMode::Rfc8489 => {
            let modern = run_udp(&mut udp, server_addr)?;
            Ok(ExecutionReport {
                requested_mode: mode,
                effective_mode: mode,
                transport,
                server: server_display,
                proxy_type: proxy_type.clone(),
                proxy_server: proxy_server.clone(),
                proxy_udp_relay,
                classic_result: None,
                modern_result: Some(modern),
                error: None,
            })
        }
        RunMode::Auto => {
            let modern = run_udp(&mut udp, server_addr)?;
            if modern.binding_test_result == BindingTestResult::Success
                && modern.filtering_behavior != FilteringBehavior::UnsupportedServer
            {
                Ok(ExecutionReport {
                    requested_mode: RunMode::Auto,
                    effective_mode: RunMode::Rfc8489,
                    transport,
                    server: server_display,
                    proxy_type: proxy_type.clone(),
                    proxy_server: proxy_server.clone(),
                    proxy_udp_relay,
                    classic_result: None,
                    modern_result: Some(modern),
                    error: None,
                })
            } else {
                let classic = run_rfc3489(&mut udp, server_addr)?;
                Ok(ExecutionReport {
                    requested_mode: RunMode::Auto,
                    effective_mode: RunMode::Rfc3489,
                    transport,
                    server: server_display,
                    proxy_type,
                    proxy_server,
                    proxy_udp_relay,
                    classic_result: Some(classic),
                    modern_result: None,
                    error: None,
                })
            }
        }
    }
}

fn execute_stream(
    mode: RunMode,
    server_display: String,
    server_addr: std::net::SocketAddr,
    timeout: std::time::Duration,
    local_bind: std::net::SocketAddr,
    proxy: Option<&Socks5ProxyConfig>,
    transport: TransportType,
    tls_server_name: Option<&str>,
) -> AppResult<ExecutionReport> {
    let proxy_server = proxy.map(|cfg| cfg.endpoint.to_string());
    let proxy_type = proxy.map(|_| "socks5".to_string());
    if mode == RunMode::Rfc3489 {
        return Err(AppError::InvalidInput(
            "RFC3489 mode supports only UDP transport".to_string(),
        ));
    }
    let modern = run_stream(
        server_addr,
        transport,
        timeout,
        local_bind,
        proxy,
        tls_server_name,
    )?;
    Ok(ExecutionReport {
        requested_mode: mode,
        effective_mode: if mode == RunMode::Auto {
            RunMode::Rfc8489
        } else {
            mode
        },
        transport,
        server: server_display,
        proxy_type,
        proxy_server,
        proxy_udp_relay: None,
        classic_result: None,
        modern_result: Some(modern),
        error: None,
    })
}

fn build_proxy_config(
    options: &nattypetester::cli::CommonArgs,
    local_bind: std::net::SocketAddr,
) -> AppResult<Option<Socks5ProxyConfig>> {
    if options.socks_user.is_some() || options.socks_pass.is_some() {
        if options.socks.is_none() {
            return Err(AppError::InvalidInput(
                "--socks-user/--socks-pass require --socks".to_string(),
            ));
        }
    }

    let Some(proxy_endpoint) = options.socks.as_ref() else {
        return Ok(None);
    };
    let (proxy_addr, _) = resolve_host_port(
        proxy_endpoint,
        1080,
        Some(IpFamilyHint::from_socket_addr(local_bind)),
    )?;
    let config = Socks5ProxyConfig {
        endpoint: proxy_addr,
        username: options.socks_user.clone(),
        password: options.socks_pass.clone(),
    };
    config.validate()?;
    Ok(Some(config))
}

fn selected_proxy_summary(
    options: &nattypetester::cli::CommonArgs,
) -> (Option<String>, Option<String>) {
    let proxy_type = options.socks.as_ref().map(|_| "socks5".to_string());
    let proxy_server = options.socks.as_ref().map(ToString::to_string);
    (proxy_type, proxy_server)
}
