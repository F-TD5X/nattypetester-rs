use serde::Serialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Auto,
    Rfc3489,
    Rfc5780,
    Rfc8489,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    Unknown,
    UnsupportedServer,
    UdpBlocked,
    OpenInternet,
    SymmetricUdpFirewall,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

impl Default for NatType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingBehavior {
    Unknown,
    UnsupportedServer,
    Direct,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    Fail,
}

impl Default for MappingBehavior {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilteringBehavior {
    Unknown,
    UnsupportedServer,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    None,
}

impl Default for FilteringBehavior {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingTestResult {
    Unknown,
    UnsupportedServer,
    Success,
    Fail,
}

impl Default for BindingTestResult {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ClassicStunResult {
    pub public_endpoint: Option<SocketAddr>,
    pub local_endpoint: Option<SocketAddr>,
    pub nat_type: NatType,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ModernStunResult {
    pub public_endpoint: Option<SocketAddr>,
    pub local_endpoint: Option<SocketAddr>,
    pub other_endpoint: Option<SocketAddr>,
    pub binding_test_result: BindingTestResult,
    pub mapping_behavior: MappingBehavior,
    pub filtering_behavior: FilteringBehavior,
}

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub requested_mode: RunMode,
    pub effective_mode: RunMode,
    pub transport: TransportType,
    pub server: String,
    pub proxy_type: Option<String>,
    pub proxy_server: Option<String>,
    pub proxy_udp_relay: Option<SocketAddr>,
    pub classic_result: Option<ClassicStunResult>,
    pub modern_result: Option<ModernStunResult>,
    pub error: Option<String>,
}

impl ExecutionReport {
    pub fn failed(
        requested_mode: RunMode,
        effective_mode: RunMode,
        transport: TransportType,
        server: String,
        error: String,
    ) -> Self {
        Self {
            requested_mode,
            effective_mode,
            transport,
            server,
            proxy_type: None,
            proxy_server: None,
            proxy_udp_relay: None,
            classic_result: None,
            modern_result: None,
            error: Some(error),
        }
    }
}
