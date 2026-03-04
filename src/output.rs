use serde::Serialize;

use crate::error::AppResult;
use crate::model::{
    BindingTestResult, ExecutionReport, FilteringBehavior, MappingBehavior, NatType,
};

pub fn render_text(report: &ExecutionReport) -> String {
    let mut lines = Vec::new();
    let mut explanation = None;
    lines.push(format!("Mode: {:?}", report.requested_mode));
    lines.push(format!("Effective Mode: {:?}", report.effective_mode));
    lines.push(format!("Transport: {:?}", report.transport));
    lines.push(format!("Server: {}", report.server));
    if let Some(proxy_type) = report.proxy_type.as_deref() {
        lines.push(format!("Proxy Type: {proxy_type}"));
    }
    if let Some(proxy_server) = report.proxy_server.as_deref() {
        lines.push(format!("Proxy Server: {proxy_server}"));
    }
    if let Some(relay) = report.proxy_udp_relay {
        lines.push(format!("SOCKS5 UDP Relay: {relay}"));
    }

    if let Some(error) = report.error.as_deref() {
        lines.push(format!("Error: {error}"));
        return lines.join("\n");
    }

    if let Some(classic) = report.classic_result.as_ref() {
        lines.push(format!("NAT Type: {}", nat_type_label(classic.nat_type)));
        explanation = Some(classic_explanation(classic.nat_type).to_string());
        lines.push(format!(
            "Local Endpoint: {}",
            format_option_endpoint(classic.local_endpoint)
        ));
        lines.push(format!(
            "Public Endpoint: {}",
            format_option_endpoint(classic.public_endpoint)
        ));
    }

    if let Some(modern) = report.modern_result.as_ref() {
        lines.push(format!("Binding Test: {:?}", modern.binding_test_result));
        lines.push(format!("Mapping Behavior: {:?}", modern.mapping_behavior));
        lines.push(format!(
            "Filtering Behavior: {:?}",
            modern.filtering_behavior
        ));
        explanation = Some(modern_explanation(
            modern.binding_test_result,
            modern.mapping_behavior,
            modern.filtering_behavior,
        ));
        lines.push(format!(
            "Local Endpoint: {}",
            format_option_endpoint(modern.local_endpoint)
        ));
        lines.push(format!(
            "Public Endpoint: {}",
            format_option_endpoint(modern.public_endpoint)
        ));
        lines.push(format!(
            "Other Endpoint: {}",
            format_option_endpoint(modern.other_endpoint)
        ));
    }

    if let Some(explanation) = explanation {
        lines.push(String::new());
        lines.push(format!("Explaination: {explanation}"));
    }

    lines.join("\n")
}

pub fn render_json(report: &ExecutionReport) -> AppResult<String> {
    let payload = JsonReport::from(report);
    Ok(serde_json::to_string_pretty(&payload)?)
}

fn format_option_endpoint(value: Option<std::net::SocketAddr>) -> String {
    value
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "-".to_string())
}

#[derive(Debug, Serialize)]
struct JsonReport {
    mode: crate::model::RunMode,
    effective_mode: crate::model::RunMode,
    transport: crate::model::TransportType,
    server: String,
    proxy_type: Option<String>,
    proxy_server: Option<String>,
    proxy_udp_relay: Option<std::net::SocketAddr>,
    local_endpoint: Option<std::net::SocketAddr>,
    public_endpoint: Option<std::net::SocketAddr>,
    other_endpoint: Option<std::net::SocketAddr>,
    nat_type: Option<crate::model::NatType>,
    binding_test_result: Option<crate::model::BindingTestResult>,
    mapping_behavior: Option<crate::model::MappingBehavior>,
    filtering_behavior: Option<crate::model::FilteringBehavior>,
    error: Option<String>,
}

impl From<&ExecutionReport> for JsonReport {
    fn from(report: &ExecutionReport) -> Self {
        let (
            local_endpoint,
            public_endpoint,
            other_endpoint,
            nat_type,
            binding,
            mapping,
            filtering,
        ) = if let Some(classic) = report.classic_result.as_ref() {
            (
                classic.local_endpoint,
                classic.public_endpoint,
                None,
                Some(classic.nat_type),
                None,
                None,
                None,
            )
        } else if let Some(modern) = report.modern_result.as_ref() {
            (
                modern.local_endpoint,
                modern.public_endpoint,
                modern.other_endpoint,
                None,
                Some(modern.binding_test_result),
                Some(modern.mapping_behavior),
                Some(modern.filtering_behavior),
            )
        } else {
            (None, None, None, None, None, None, None)
        };

        Self {
            mode: report.requested_mode,
            effective_mode: report.effective_mode,
            transport: report.transport,
            server: report.server.clone(),
            proxy_type: report.proxy_type.clone(),
            proxy_server: report.proxy_server.clone(),
            proxy_udp_relay: report.proxy_udp_relay,
            local_endpoint,
            public_endpoint,
            other_endpoint,
            nat_type,
            binding_test_result: binding,
            mapping_behavior: mapping,
            filtering_behavior: filtering,
            error: report.error.clone(),
        }
    }
}

fn nat_type_label(nat_type: NatType) -> &'static str {
    match nat_type {
        NatType::SymmetricUdpFirewall => {
            "SymmetricUdpFirewall (no NAT mapping; symmetric UDP filtering/firewall)"
        }
        NatType::Symmetric => "Symmetric (symmetric NAT mapping)",
        NatType::Unknown => "Unknown",
        NatType::UnsupportedServer => "UnsupportedServer",
        NatType::UdpBlocked => "UdpBlocked",
        NatType::OpenInternet => "OpenInternet",
        NatType::FullCone => "FullCone",
        NatType::RestrictedCone => "RestrictedCone",
        NatType::PortRestrictedCone => "PortRestrictedCone",
    }
}

fn classic_explanation(nat_type: NatType) -> &'static str {
    match nat_type {
        NatType::OpenInternet => "No NAT or UDP firewall detected.",
        NatType::FullCone => "Stable public mapping; inbound UDP is broadly reachable.",
        NatType::RestrictedCone => {
            "Stable public mapping; inbound UDP allowed from contacted IP addresses."
        }
        NatType::PortRestrictedCone => {
            "Stable public mapping; inbound UDP allowed only from contacted IP:port pairs."
        }
        NatType::Symmetric => "Public mapping changes by destination; peer reachability is limited.",
        NatType::SymmetricUdpFirewall => {
            "No NAT mapping observed, but inbound UDP is filtered unless traffic was initiated."
        }
        NatType::UdpBlocked => "UDP appears blocked or unavailable.",
        NatType::UnsupportedServer => {
            "Server does not support the tests needed to classify NAT type."
        }
        NatType::Unknown => "Result is inconclusive.",
    }
}

fn modern_explanation(
    binding: BindingTestResult,
    mapping: MappingBehavior,
    filtering: FilteringBehavior,
) -> String {
    let binding_text = match binding {
        BindingTestResult::Success => "binding succeeded",
        BindingTestResult::Fail => "binding failed",
        BindingTestResult::UnsupportedServer => "binding test unsupported by server",
        BindingTestResult::Unknown => "binding status unknown",
    };
    let mapping_text = match mapping {
        MappingBehavior::Direct => "no NAT mapping observed",
        MappingBehavior::EndpointIndependent => "mapping is endpoint-independent",
        MappingBehavior::AddressDependent => "mapping depends on destination IP",
        MappingBehavior::AddressAndPortDependent => "mapping depends on destination IP and port",
        MappingBehavior::Fail => "mapping behavior test failed",
        MappingBehavior::UnsupportedServer => "mapping behavior unsupported by server",
        MappingBehavior::Unknown => "mapping behavior unknown",
    };
    let filtering_text = match filtering {
        FilteringBehavior::None => "no UDP filtering observed",
        FilteringBehavior::EndpointIndependent => "filtering is endpoint-independent",
        FilteringBehavior::AddressDependent => "filtering depends on source IP",
        FilteringBehavior::AddressAndPortDependent => "filtering depends on source IP and port",
        FilteringBehavior::UnsupportedServer => "filtering behavior unsupported by server",
        FilteringBehavior::Unknown => "filtering behavior unknown",
    };
    format!("{binding_text}; {mapping_text}; {filtering_text}.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClassicStunResult, ModernStunResult, RunMode, TransportType};

    #[test]
    fn symmetric_udp_firewall_label_is_explicit() {
        let report = ExecutionReport {
            requested_mode: RunMode::Rfc3489,
            effective_mode: RunMode::Rfc3489,
            transport: TransportType::Udp,
            server: "stun.example.org:3478".to_string(),
            proxy_type: None,
            proxy_server: None,
            proxy_udp_relay: None,
            classic_result: Some(ClassicStunResult {
                nat_type: NatType::SymmetricUdpFirewall,
                ..Default::default()
            }),
            modern_result: None,
            error: None,
        };

        let text = render_text(&report);
        assert!(text.contains("no NAT mapping"));
        assert!(text.contains("symmetric UDP filtering/firewall"));
    }

    #[test]
    fn symmetric_nat_label_is_explicit() {
        let report = ExecutionReport {
            requested_mode: RunMode::Rfc3489,
            effective_mode: RunMode::Rfc3489,
            transport: TransportType::Udp,
            server: "stun.example.org:3478".to_string(),
            proxy_type: None,
            proxy_server: None,
            proxy_udp_relay: None,
            classic_result: Some(ClassicStunResult {
                nat_type: NatType::Symmetric,
                ..Default::default()
            }),
            modern_result: None,
            error: None,
        };

        let text = render_text(&report);
        assert!(text.contains("symmetric NAT mapping"));
    }

    #[test]
    fn classic_text_output_includes_explanation() {
        let report = ExecutionReport {
            requested_mode: RunMode::Rfc3489,
            effective_mode: RunMode::Rfc3489,
            transport: TransportType::Udp,
            server: "stun.example.org:3478".to_string(),
            proxy_type: None,
            proxy_server: None,
            proxy_udp_relay: None,
            classic_result: Some(ClassicStunResult {
                nat_type: NatType::OpenInternet,
                ..Default::default()
            }),
            modern_result: None,
            error: None,
        };

        let text = render_text(&report);
        assert!(text.contains("\n\nExplaination: No NAT or UDP firewall detected."));
    }

    #[test]
    fn modern_text_output_includes_explanation() {
        let report = ExecutionReport {
            requested_mode: RunMode::Rfc8489,
            effective_mode: RunMode::Rfc8489,
            transport: TransportType::Udp,
            server: "stun.example.org:3478".to_string(),
            proxy_type: None,
            proxy_server: None,
            proxy_udp_relay: None,
            classic_result: None,
            modern_result: Some(ModernStunResult {
                binding_test_result: BindingTestResult::Success,
                mapping_behavior: MappingBehavior::EndpointIndependent,
                filtering_behavior: FilteringBehavior::EndpointIndependent,
                ..Default::default()
            }),
            error: None,
        };

        let text = render_text(&report);
        assert!(text.contains(
            "\n\nExplaination: binding succeeded; mapping is endpoint-independent; filtering is endpoint-independent."
        ));
    }
}
