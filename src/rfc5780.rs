use std::net::SocketAddr;
use std::time::Duration;

use crate::error::AppResult;
use crate::model::{
    BindingTestResult, FilteringBehavior, MappingBehavior, ModernStunResult, TransportType,
};
use crate::proxy::socks5::Socks5ProxyConfig;
use crate::stun::wire::{MAGIC_COOKIE, StunMessage, build_change_request_attribute};
use crate::transport::tcp::request_stun_over_stream;
use crate::transport::udp::UdpTransport;

pub fn run_udp(transport: &mut UdpTransport, remote: SocketAddr) -> AppResult<ModernStunResult> {
    let binding = binding_test_udp(transport, remote, remote)?;
    let mut state = binding.clone();

    if state.binding_test_result != BindingTestResult::Success {
        return Ok(state);
    }

    state.filtering_behavior = run_filtering_behavior_udp(transport, remote, &binding)?;
    if state.filtering_behavior == FilteringBehavior::UnsupportedServer {
        return Ok(state);
    }

    state.mapping_behavior = run_mapping_behavior_udp(transport, remote, &binding)?;
    Ok(state)
}

pub fn run_stream(
    remote: SocketAddr,
    transport: TransportType,
    timeout: Duration,
    local_bind: SocketAddr,
    proxy: Option<&Socks5ProxyConfig>,
    tls_server_name: Option<&str>,
) -> AppResult<ModernStunResult> {
    let mut last_local = local_bind;
    let binding = binding_test_stream(
        remote,
        remote,
        transport,
        timeout,
        &mut last_local,
        proxy,
        tls_server_name,
    )?;

    let mut state = binding.clone();
    if state.binding_test_result == BindingTestResult::Success {
        state.mapping_behavior = run_mapping_behavior_stream(
            remote,
            transport,
            timeout,
            &mut last_local,
            proxy,
            tls_server_name,
            &binding,
        )?;
    }
    state.filtering_behavior = FilteringBehavior::None;
    Ok(state)
}

fn binding_test_udp(
    transport: &mut UdpTransport,
    send_remote: SocketAddr,
    expected_remote: SocketAddr,
) -> AppResult<ModernStunResult> {
    let request = StunMessage::new_binding_request(MAGIC_COOKIE);
    let encoded = request.encode()?;
    let datagram = transport.request(&encoded, send_remote, expected_remote)?;
    let mut result = ModernStunResult::default();
    let Some(datagram) = datagram else {
        result.binding_test_result = BindingTestResult::Fail;
        return Ok(result);
    };
    let parsed = match StunMessage::decode(&datagram.payload) {
        Ok(parsed) => parsed,
        Err(_) => {
            result.binding_test_result = BindingTestResult::Fail;
            return Ok(result);
        }
    };
    if !parsed.same_transaction(&request) {
        result.binding_test_result = BindingTestResult::Fail;
        return Ok(result);
    }

    result.local_endpoint = Some(datagram.local);
    result.public_endpoint = parsed.xor_mapped_or_mapped_address();
    result.other_endpoint = parsed.other_or_changed_address();
    result.binding_test_result = if result.public_endpoint.is_some() {
        BindingTestResult::Success
    } else {
        BindingTestResult::UnsupportedServer
    };
    Ok(result)
}

fn binding_test_stream(
    send_remote: SocketAddr,
    expected_remote: SocketAddr,
    transport: TransportType,
    timeout: Duration,
    last_local: &mut SocketAddr,
    proxy: Option<&Socks5ProxyConfig>,
    tls_server_name: Option<&str>,
) -> AppResult<ModernStunResult> {
    let request = StunMessage::new_binding_request(MAGIC_COOKIE);
    let encoded = request.encode()?;
    let datagram = request_stun_over_stream(
        &encoded,
        send_remote,
        timeout,
        *last_local,
        proxy,
        matches!(transport, TransportType::Tls),
        tls_server_name,
    )?;
    let mut result = ModernStunResult::default();
    let Some(frame) = datagram else {
        result.binding_test_result = BindingTestResult::Fail;
        return Ok(result);
    };
    *last_local = frame.local;

    let parsed = match StunMessage::decode(&frame.payload) {
        Ok(parsed) => parsed,
        Err(_) => {
            result.binding_test_result = BindingTestResult::Fail;
            return Ok(result);
        }
    };
    if !parsed.same_transaction(&request) {
        result.binding_test_result = BindingTestResult::Fail;
        return Ok(result);
    }

    result.local_endpoint = Some(frame.local);
    result.public_endpoint = parsed.xor_mapped_or_mapped_address();
    result.other_endpoint = parsed.other_or_changed_address();
    result.binding_test_result = if result.public_endpoint.is_some() {
        BindingTestResult::Success
    } else {
        BindingTestResult::UnsupportedServer
    };
    let _ = expected_remote;
    Ok(result)
}

fn run_filtering_behavior_udp(
    transport: &mut UdpTransport,
    remote: SocketAddr,
    binding: &ModernStunResult,
) -> AppResult<FilteringBehavior> {
    let Some(other) = binding.other_endpoint else {
        return Ok(FilteringBehavior::UnsupportedServer);
    };
    if !has_valid_other_address(Some(other), remote) {
        return Ok(FilteringBehavior::UnsupportedServer);
    }

    let response2 = filtering_request_udp(transport, remote, other, true, true)?;
    if let Some(response2) = response2 {
        return Ok(if response2 == other {
            FilteringBehavior::EndpointIndependent
        } else {
            FilteringBehavior::UnsupportedServer
        });
    }

    let response3 = filtering_request_udp(transport, remote, remote, false, true)?;
    Ok(decide_udp_filtering_from_remotes(
        remote,
        Some(other),
        None,
        response3,
    ))
}

fn filtering_request_udp(
    transport: &mut UdpTransport,
    send_remote: SocketAddr,
    expected_remote: SocketAddr,
    change_ip: bool,
    change_port: bool,
) -> AppResult<Option<SocketAddr>> {
    let mut request = StunMessage::new_binding_request(MAGIC_COOKIE);
    request.add_attribute(build_change_request_attribute(change_ip, change_port));
    let encoded = request.encode()?;
    let datagram = transport.request(&encoded, send_remote, expected_remote)?;
    let Some(datagram) = datagram else {
        return Ok(None);
    };
    let parsed = match StunMessage::decode(&datagram.payload) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };
    if !parsed.same_transaction(&request) {
        return Ok(None);
    }
    Ok(Some(datagram.remote))
}

fn run_mapping_behavior_udp(
    transport: &mut UdpTransport,
    remote: SocketAddr,
    binding: &ModernStunResult,
) -> AppResult<MappingBehavior> {
    let Some(other) = binding.other_endpoint else {
        return Ok(MappingBehavior::UnsupportedServer);
    };
    if !has_valid_other_address(Some(other), remote) {
        return Ok(MappingBehavior::UnsupportedServer);
    }

    if binding.public_endpoint == binding.local_endpoint {
        return Ok(MappingBehavior::Direct);
    }

    let second = binding_test_udp(
        transport,
        SocketAddr::new(other.ip(), remote.port()),
        SocketAddr::new(other.ip(), remote.port()),
    )?;
    if second.binding_test_result != BindingTestResult::Success {
        return Ok(MappingBehavior::Fail);
    }
    if second.public_endpoint == binding.public_endpoint {
        return Ok(MappingBehavior::EndpointIndependent);
    }

    let third = binding_test_udp(transport, other, other)?;
    Ok(decide_mapping_from_samples(
        remote,
        binding,
        &second,
        Some(&third),
    ))
}

fn run_mapping_behavior_stream(
    remote: SocketAddr,
    transport: TransportType,
    timeout: Duration,
    last_local: &mut SocketAddr,
    proxy: Option<&Socks5ProxyConfig>,
    tls_server_name: Option<&str>,
    binding: &ModernStunResult,
) -> AppResult<MappingBehavior> {
    let Some(other) = binding.other_endpoint else {
        return Ok(MappingBehavior::UnsupportedServer);
    };
    if !has_valid_other_address(Some(other), remote) {
        return Ok(MappingBehavior::UnsupportedServer);
    }

    if binding.public_endpoint == binding.local_endpoint {
        return Ok(MappingBehavior::Direct);
    }

    let second = binding_test_stream(
        SocketAddr::new(other.ip(), remote.port()),
        SocketAddr::new(other.ip(), remote.port()),
        transport,
        timeout,
        last_local,
        proxy,
        tls_server_name,
    )?;
    if second.binding_test_result != BindingTestResult::Success {
        return Ok(MappingBehavior::Fail);
    }
    if second.public_endpoint == binding.public_endpoint {
        return Ok(MappingBehavior::EndpointIndependent);
    }

    let third = binding_test_stream(
        other,
        other,
        transport,
        timeout,
        last_local,
        proxy,
        tls_server_name,
    )?;
    Ok(decide_mapping_from_samples(
        remote,
        binding,
        &second,
        Some(&third),
    ))
}

pub fn has_valid_other_address(other: Option<SocketAddr>, remote: SocketAddr) -> bool {
    let Some(other) = other else {
        return false;
    };
    other.ip() != remote.ip() && other.port() != remote.port()
}

pub fn decide_udp_filtering_from_remotes(
    remote: SocketAddr,
    other: Option<SocketAddr>,
    response2_remote: Option<SocketAddr>,
    response3_remote: Option<SocketAddr>,
) -> FilteringBehavior {
    let Some(other) = other else {
        return FilteringBehavior::UnsupportedServer;
    };
    if !has_valid_other_address(Some(other), remote) {
        return FilteringBehavior::UnsupportedServer;
    }
    if let Some(response2_remote) = response2_remote {
        return if response2_remote == other {
            FilteringBehavior::EndpointIndependent
        } else {
            FilteringBehavior::UnsupportedServer
        };
    }
    match response3_remote {
        None => FilteringBehavior::AddressAndPortDependent,
        Some(response3_remote)
            if response3_remote.ip() == remote.ip() && response3_remote.port() != remote.port() =>
        {
            FilteringBehavior::AddressDependent
        }
        Some(_) => FilteringBehavior::UnsupportedServer,
    }
}

pub fn decide_mapping_from_samples(
    remote: SocketAddr,
    initial: &ModernStunResult,
    second: &ModernStunResult,
    third: Option<&ModernStunResult>,
) -> MappingBehavior {
    if initial.binding_test_result != BindingTestResult::Success {
        return MappingBehavior::Unknown;
    }
    if !has_valid_other_address(initial.other_endpoint, remote) {
        return MappingBehavior::UnsupportedServer;
    }
    if initial.public_endpoint == initial.local_endpoint {
        return MappingBehavior::Direct;
    }
    if second.binding_test_result != BindingTestResult::Success {
        return MappingBehavior::Fail;
    }
    if second.public_endpoint == initial.public_endpoint {
        return MappingBehavior::EndpointIndependent;
    }
    let Some(third) = third else {
        return MappingBehavior::Fail;
    };
    if third.binding_test_result != BindingTestResult::Success {
        return MappingBehavior::Fail;
    }
    if third.public_endpoint == second.public_endpoint {
        MappingBehavior::AddressDependent
    } else {
        MappingBehavior::AddressAndPortDependent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modern(
        local: Option<&str>,
        public: Option<&str>,
        other: Option<&str>,
        binding: BindingTestResult,
    ) -> ModernStunResult {
        ModernStunResult {
            local_endpoint: local.map(|s| s.parse().unwrap()),
            public_endpoint: public.map(|s| s.parse().unwrap()),
            other_endpoint: other.map(|s| s.parse().unwrap()),
            binding_test_result: binding,
            ..Default::default()
        }
    }

    #[test]
    fn filtering_endpoint_independent() {
        let remote: SocketAddr = "198.51.100.10:3478".parse().unwrap();
        let other: SocketAddr = "198.51.100.11:3479".parse().unwrap();
        assert_eq!(
            decide_udp_filtering_from_remotes(remote, Some(other), Some(other), None),
            FilteringBehavior::EndpointIndependent
        );
    }

    #[test]
    fn filtering_address_dependent() {
        let remote: SocketAddr = "198.51.100.10:3478".parse().unwrap();
        let other: SocketAddr = "198.51.100.11:3479".parse().unwrap();
        let response3: SocketAddr = "198.51.100.10:3480".parse().unwrap();
        assert_eq!(
            decide_udp_filtering_from_remotes(remote, Some(other), None, Some(response3)),
            FilteringBehavior::AddressDependent
        );
    }

    #[test]
    fn mapping_address_and_port_dependent() {
        let remote: SocketAddr = "198.51.100.10:3478".parse().unwrap();
        let initial = modern(
            Some("10.0.0.2:50000"),
            Some("198.51.100.20:62000"),
            Some("198.51.100.11:3479"),
            BindingTestResult::Success,
        );
        let second = modern(
            Some("10.0.0.2:50000"),
            Some("198.51.100.20:62001"),
            Some("198.51.100.11:3479"),
            BindingTestResult::Success,
        );
        let third = modern(
            Some("10.0.0.2:50000"),
            Some("198.51.100.20:62002"),
            Some("198.51.100.11:3479"),
            BindingTestResult::Success,
        );
        assert_eq!(
            decide_mapping_from_samples(remote, &initial, &second, Some(&third)),
            MappingBehavior::AddressAndPortDependent
        );
    }

    #[test]
    fn mapping_fail_when_second_binding_fails() {
        let remote: SocketAddr = "198.51.100.10:3478".parse().unwrap();
        let initial = modern(
            Some("10.0.0.2:50000"),
            Some("198.51.100.20:62000"),
            Some("198.51.100.11:3479"),
            BindingTestResult::Success,
        );
        let second = modern(None, None, None, BindingTestResult::Fail);
        assert_eq!(
            decide_mapping_from_samples(remote, &initial, &second, None),
            MappingBehavior::Fail
        );
    }
}
