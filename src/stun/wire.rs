use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::random;

use crate::error::{AppError, AppResult};

pub const MESSAGE_TYPE_BINDING_REQUEST: u16 = 0x0001;
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
pub const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_OTHER_ADDRESS: u16 = 0x802C;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunAttribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub message_type: u16,
    pub magic_cookie: u32,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    pub fn new_binding_request(magic_cookie: u32) -> Self {
        Self {
            message_type: MESSAGE_TYPE_BINDING_REQUEST,
            magic_cookie,
            transaction_id: random::<[u8; 12]>(),
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, attribute: StunAttribute) {
        self.attributes.push(attribute);
    }

    pub fn same_transaction(&self, other: &Self) -> bool {
        self.magic_cookie == other.magic_cookie && self.transaction_id == other.transaction_id
    }

    pub fn encoded_len(&self) -> usize {
        20 + self
            .attributes
            .iter()
            .map(|attr| {
                let base = 4 + attr.value.len();
                let padding = (4 - base % 4) % 4;
                base + padding
            })
            .sum::<usize>()
    }

    pub fn encode(&self) -> AppResult<Vec<u8>> {
        let payload_len = self.encoded_len() - 20;
        if payload_len > u16::MAX as usize {
            return Err(AppError::Protocol(
                "STUN payload exceeds u16 length limit".to_string(),
            ));
        }

        let mut buffer = Vec::with_capacity(self.encoded_len());
        buffer.extend_from_slice(&self.message_type.to_be_bytes());
        buffer.extend_from_slice(&(payload_len as u16).to_be_bytes());
        buffer.extend_from_slice(&self.magic_cookie.to_be_bytes());
        buffer.extend_from_slice(&self.transaction_id);

        for attr in &self.attributes {
            if attr.value.len() > u16::MAX as usize {
                return Err(AppError::Protocol(format!(
                    "attribute 0x{:04x} is too large",
                    attr.attr_type
                )));
            }
            buffer.extend_from_slice(&attr.attr_type.to_be_bytes());
            buffer.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            buffer.extend_from_slice(&attr.value);
            let base = 4 + attr.value.len();
            let padding = (4 - base % 4) % 4;
            if padding > 0 {
                buffer.resize(buffer.len() + padding, 0);
            }
        }

        Ok(buffer)
    }

    pub fn decode(raw: &[u8]) -> AppResult<Self> {
        if raw.len() < 20 {
            return Err(AppError::Protocol(
                "buffer shorter than STUN header".to_string(),
            ));
        }

        let message_type = u16::from_be_bytes([raw[0], raw[1]]);
        let payload_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        let total_len = 20 + payload_len;
        if raw.len() < total_len {
            return Err(AppError::Protocol(
                "incomplete STUN message payload".to_string(),
            ));
        }

        let magic_cookie = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let mut transaction_id = [0_u8; 12];
        transaction_id.copy_from_slice(&raw[8..20]);

        let mut attributes = Vec::new();
        let mut cursor = 20;
        while cursor < total_len {
            if cursor + 4 > total_len {
                return Err(AppError::Protocol(
                    "truncated STUN attribute header".to_string(),
                ));
            }
            let attr_type = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
            let attr_len = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]) as usize;
            let value_start = cursor + 4;
            let value_end = value_start + attr_len;
            if value_end > total_len {
                return Err(AppError::Protocol(
                    "truncated STUN attribute value".to_string(),
                ));
            }
            attributes.push(StunAttribute {
                attr_type,
                value: raw[value_start..value_end].to_vec(),
            });
            cursor = value_end;
            let padding = (4 - (cursor % 4)) % 4;
            cursor += padding;
        }

        Ok(Self {
            message_type,
            magic_cookie,
            transaction_id,
            attributes,
        })
    }

    pub fn attribute(&self, attr_type: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|attr| attr.attr_type == attr_type)
            .map(|attr| attr.value.as_slice())
    }

    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.attribute(ATTR_MAPPED_ADDRESS)
            .and_then(parse_address_attribute)
    }

    pub fn changed_address(&self) -> Option<SocketAddr> {
        self.attribute(ATTR_CHANGED_ADDRESS)
            .and_then(parse_address_attribute)
    }

    pub fn xor_mapped_or_mapped_address(&self) -> Option<SocketAddr> {
        self.attribute(ATTR_XOR_MAPPED_ADDRESS)
            .and_then(|value| {
                parse_xor_address_attribute(value, self.magic_cookie, self.transaction_id)
            })
            .or_else(|| self.mapped_address())
    }

    pub fn other_or_changed_address(&self) -> Option<SocketAddr> {
        self.attribute(ATTR_OTHER_ADDRESS)
            .and_then(parse_address_attribute)
            .or_else(|| self.changed_address())
    }
}

pub fn build_change_request_attribute(change_ip: bool, change_port: bool) -> StunAttribute {
    let flags = ((change_ip as u8) << 2) | ((change_port as u8) << 1);
    StunAttribute {
        attr_type: ATTR_CHANGE_REQUEST,
        value: vec![0, 0, 0, flags],
    }
}

pub fn parse_address_attribute(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        0x01 if value.len() == 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            port,
        )),
        0x02 if value.len() == 20 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

pub fn parse_xor_address_attribute(
    value: &[u8],
    magic_cookie: u32,
    transaction_id: [u8; 12],
) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }

    let family = value[1];
    let mut xor_key = [0_u8; 16];
    xor_key[..4].copy_from_slice(&magic_cookie.to_be_bytes());
    xor_key[4..].copy_from_slice(&transaction_id);

    let encoded_port = u16::from_be_bytes([value[2], value[3]]);
    let port = encoded_port ^ u16::from_be_bytes([xor_key[0], xor_key[1]]);

    match family {
        0x01 if value.len() == 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                value[4] ^ xor_key[0],
                value[5] ^ xor_key[1],
                value[6] ^ xor_key[2],
                value[7] ^ xor_key[3],
            )),
            port,
        )),
        0x02 if value.len() == 20 => {
            let mut octets = [0_u8; 16];
            for (idx, octet) in octets.iter_mut().enumerate() {
                *octet = value[4 + idx] ^ xor_key[idx];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_message_roundtrip_with_change_request() {
        let mut request = StunMessage::new_binding_request(0);
        request.transaction_id = [9; 12];
        request.add_attribute(build_change_request_attribute(true, true));

        let encoded = request.encode().expect("encode");
        let decoded = StunMessage::decode(&encoded).expect("decode");

        assert_eq!(decoded.message_type, request.message_type);
        assert_eq!(decoded.magic_cookie, 0);
        assert_eq!(decoded.transaction_id, [9; 12]);
        assert_eq!(
            decoded.attribute(ATTR_CHANGE_REQUEST),
            Some(&[0, 0, 0, 0b0000_0110][..])
        );
    }

    #[test]
    fn parse_ipv4_mapped_attribute() {
        let attr = [0_u8, 0x01, 0x12, 0x34, 1, 2, 3, 4];
        let endpoint = parse_address_attribute(&attr).expect("endpoint");
        assert_eq!(endpoint, "1.2.3.4:4660".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_xor_ipv4_attribute() {
        let cookie = MAGIC_COOKIE;
        let tx = [1_u8; 12];
        let ip = [203_u8, 0, 113, 7];
        let port = 3478_u16;
        let mut value = [0_u8; 8];
        value[1] = 0x01;
        let cookie_bytes = cookie.to_be_bytes();
        let xor_port = port ^ u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);
        value[2..4].copy_from_slice(&xor_port.to_be_bytes());
        for idx in 0..4 {
            value[4 + idx] = ip[idx] ^ cookie_bytes[idx];
        }

        let endpoint = parse_xor_address_attribute(&value, cookie, tx).expect("endpoint");
        assert_eq!(endpoint, "203.0.113.7:3478".parse::<SocketAddr>().unwrap());
    }
}
