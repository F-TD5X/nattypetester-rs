use std::net::SocketAddr;

use crate::error::AppResult;
use crate::model::{ClassicStunResult, NatType};
use crate::stun::wire::{StunMessage, build_change_request_attribute};
use crate::transport::udp::UdpTransport;

#[derive(Debug, Clone)]
pub struct TestSnapshot {
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub mapped_address: Option<SocketAddr>,
    pub changed_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionInput {
    pub test1: Option<TestSnapshot>,
    pub test2: Option<TestSnapshot>,
    pub test1_2: Option<TestSnapshot>,
    pub test3: Option<TestSnapshot>,
}

pub fn run_rfc3489(
    transport: &mut UdpTransport,
    remote: SocketAddr,
) -> AppResult<ClassicStunResult> {
    let test1 = request_test(transport, remote, remote, false, false)?;
    let test2 = if let Some(snapshot) = test1.as_ref() {
        if let Some(changed) = snapshot.changed_address {
            request_test(transport, remote, changed, true, true)?
        } else {
            None
        }
    } else {
        None
    };
    let test1_2 = if test2.is_none() {
        if let Some(snapshot) = test1.as_ref() {
            if let Some(changed) = snapshot.changed_address {
                request_test(transport, changed, changed, false, false)?
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let test3 = if test2.is_none() && test1.is_some() {
        request_test(transport, remote, remote, false, true)?
    } else {
        None
    };

    Ok(decide_nat_type(&DecisionInput {
        test1,
        test2,
        test1_2,
        test3,
    }))
}

pub fn decide_nat_type(input: &DecisionInput) -> ClassicStunResult {
    let Some(response1) = input.test1.as_ref() else {
        return ClassicStunResult {
            nat_type: NatType::UdpBlocked,
            ..Default::default()
        };
    };

    let mut result = ClassicStunResult {
        local_endpoint: Some(response1.local),
        public_endpoint: response1.mapped_address,
        nat_type: NatType::Unknown,
    };

    let mapped_address1 = response1.mapped_address;
    let changed_address = response1.changed_address;

    if mapped_address1.is_none()
        || changed_address.is_none()
        || changed_address.map(|ep| ep.ip()) == Some(response1.remote.ip())
        || changed_address.map(|ep| ep.port()) == Some(response1.remote.port())
    {
        result.nat_type = NatType::UnsupportedServer;
        return result;
    }

    let response2 = input.test2.as_ref();
    let mapped_address2 = response2.and_then(|snapshot| snapshot.mapped_address);

    if let Some(snapshot2) = response2
        && (response1.remote.ip() == snapshot2.remote.ip()
            || response1.remote.port() == snapshot2.remote.port())
    {
        result.nat_type = NatType::UnsupportedServer;
        result.public_endpoint = mapped_address2;
        return result;
    }

    if mapped_address1 == Some(response1.local) {
        if response2.is_none() {
            result.nat_type = NatType::SymmetricUdpFirewall;
            result.public_endpoint = mapped_address1;
        } else {
            result.nat_type = NatType::OpenInternet;
            result.public_endpoint = mapped_address2;
        }
        return result;
    }

    if response2.is_some() {
        result.nat_type = NatType::FullCone;
        result.public_endpoint = mapped_address2;
        return result;
    }

    let mapped_address1_2 = input
        .test1_2
        .as_ref()
        .and_then(|snapshot| snapshot.mapped_address);
    let Some(mapped_address1_2) = mapped_address1_2 else {
        result.nat_type = NatType::Unknown;
        return result;
    };

    if Some(mapped_address1_2) != mapped_address1 {
        result.nat_type = NatType::Symmetric;
        result.public_endpoint = Some(mapped_address1_2);
        return result;
    }

    if let Some(response3) = input.test3.as_ref()
        && let Some(mapped_address3) = response3.mapped_address
        && response3.remote.ip() == response1.remote.ip()
        && response3.remote.port() != response1.remote.port()
    {
        result.nat_type = NatType::RestrictedCone;
        result.public_endpoint = Some(mapped_address3);
        return result;
    }

    result.nat_type = NatType::PortRestrictedCone;
    result.public_endpoint = Some(mapped_address1_2);
    result
}

fn request_test(
    transport: &mut UdpTransport,
    send_remote: SocketAddr,
    expected_remote: SocketAddr,
    change_ip: bool,
    change_port: bool,
) -> AppResult<Option<TestSnapshot>> {
    let mut request = StunMessage::new_binding_request(0);
    if change_ip || change_port {
        request.add_attribute(build_change_request_attribute(change_ip, change_port));
    }
    let encoded = request.encode()?;
    let Some(datagram) = transport.request(&encoded, send_remote, expected_remote)? else {
        return Ok(None);
    };
    let parsed = match StunMessage::decode(&datagram.payload) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };
    if !parsed.same_transaction(&request) {
        return Ok(None);
    }
    Ok(Some(TestSnapshot {
        remote: datagram.remote,
        local: datagram.local,
        mapped_address: parsed.mapped_address(),
        changed_address: parsed.changed_address(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        remote: &str,
        local: &str,
        mapped: Option<&str>,
        changed: Option<&str>,
    ) -> TestSnapshot {
        TestSnapshot {
            remote: remote.parse().unwrap(),
            local: local.parse().unwrap(),
            mapped_address: mapped.map(|s| s.parse().unwrap()),
            changed_address: changed.map(|s| s.parse().unwrap()),
        }
    }

    #[test]
    fn classify_udp_blocked() {
        let output = decide_nat_type(&DecisionInput::default());
        assert_eq!(output.nat_type, NatType::UdpBlocked);
    }

    #[test]
    fn classify_open_internet() {
        let input = DecisionInput {
            test1: Some(snapshot(
                "198.51.100.10:3478",
                "203.0.113.2:45000",
                Some("203.0.113.2:45000"),
                Some("198.51.100.11:3479"),
            )),
            test2: Some(snapshot(
                "198.51.100.11:3479",
                "203.0.113.2:45000",
                Some("203.0.113.2:45000"),
                None,
            )),
            ..Default::default()
        };
        let output = decide_nat_type(&input);
        assert_eq!(output.nat_type, NatType::OpenInternet);
    }

    #[test]
    fn classify_symmetric_nat() {
        let input = DecisionInput {
            test1: Some(snapshot(
                "198.51.100.10:3478",
                "10.0.0.2:50000",
                Some("198.51.100.20:62000"),
                Some("198.51.100.11:3479"),
            )),
            test1_2: Some(snapshot(
                "198.51.100.11:3479",
                "10.0.0.2:50000",
                Some("198.51.100.20:62001"),
                None,
            )),
            ..Default::default()
        };
        let output = decide_nat_type(&input);
        assert_eq!(output.nat_type, NatType::Symmetric);
    }

    #[test]
    fn classify_port_restricted_cone() {
        let input = DecisionInput {
            test1: Some(snapshot(
                "198.51.100.10:3478",
                "10.0.0.2:50000",
                Some("198.51.100.20:62000"),
                Some("198.51.100.11:3479"),
            )),
            test1_2: Some(snapshot(
                "198.51.100.11:3479",
                "10.0.0.2:50000",
                Some("198.51.100.20:62000"),
                None,
            )),
            test3: None,
            ..Default::default()
        };
        let output = decide_nat_type(&input);
        assert_eq!(output.nat_type, NatType::PortRestrictedCone);
    }
}
