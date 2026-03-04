use std::net::SocketAddr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::model::{RunMode, TransportType};
use crate::net::HostPort;

#[derive(Debug, Parser)]
#[command(
    name = "nattypetester",
    version,
    about = "NAT type tester CLI (RFC3489/RFC5780/RFC8489)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub options: CommonArgs,
}

#[derive(Debug, Subcommand, Clone, Copy)]
pub enum Command {
    Auto,
    Rfc3489,
    Rfc5780,
    Rfc8489,
}

#[derive(Debug, Args, Clone)]
pub struct CommonArgs {
    #[arg(long, global = true)]
    pub server: Option<HostPort>,

    #[arg(
        short = '4',
        global = true,
        conflicts_with = "ipv6",
        help = "Force IPv4 address family"
    )]
    pub ipv4: bool,

    #[arg(
        short = '6',
        global = true,
        conflicts_with = "ipv4",
        help = "Force IPv6 address family"
    )]
    pub ipv6: bool,

    #[arg(short = 't', long, value_enum, default_value = "udp", global = true)]
    pub transport: TransportArg,

    #[arg(
        long,
        default_value = "3s",
        value_parser = parse_duration,
        global = true
    )]
    pub timeout: Duration,

    #[arg(long, global = true)]
    pub local_endpoint: Option<SocketAddr>,

    #[arg(long, global = true)]
    pub json: bool,

    #[arg(long, global = true)]
    pub socks: Option<HostPort>,

    #[arg(long, global = true)]
    pub socks_user: Option<String>,

    #[arg(long, global = true)]
    pub socks_pass: Option<String>,

    #[arg(long, global = true)]
    pub sni: Option<String>,
}

impl Default for CommonArgs {
    fn default() -> Self {
        Self {
            server: None,
            ipv4: false,
            ipv6: false,
            transport: TransportArg::Udp,
            timeout: Duration::from_secs(3),
            local_endpoint: None,
            json: false,
            socks: None,
            socks_user: None,
            socks_pass: None,
            sni: None,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TransportArg {
    Udp,
    Tcp,
    Tls,
}

impl From<TransportArg> for TransportType {
    fn from(value: TransportArg) -> Self {
        match value {
            TransportArg::Udp => TransportType::Udp,
            TransportArg::Tcp => TransportType::Tcp,
            TransportArg::Tls => TransportType::Tls,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedCli {
    pub mode: RunMode,
    pub options: CommonArgs,
}

impl Cli {
    pub fn resolve(self) -> ResolvedCli {
        let mode = match self.command.unwrap_or(Command::Auto) {
            Command::Auto => RunMode::Auto,
            Command::Rfc3489 => RunMode::Rfc3489,
            Command::Rfc5780 => RunMode::Rfc5780,
            Command::Rfc8489 => RunMode::Rfc8489,
        };
        ResolvedCli {
            mode,
            options: self.options,
        }
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|err| err.to_string())
}
