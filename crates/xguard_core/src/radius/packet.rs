//! RADIUS packets: the parts of RFC 2865 (Access-Request with PAP) and RFC 3579
//! (Message-Authenticator) that an MFA client needs.
//!
//! Pure functions, no I/O. Requests always carry a Message-Authenticator as their first
//! attribute, and [`verify_response`] refuses any answer that lacks a valid one or a valid
//! Response Authenticator (BlastRADIUS, CVE-2024-3596).

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};

use crate::sso::constant_time_eq;

/// RFC 2865 §3: the largest packet either side may send.
pub const MAX_PACKET_LEN: usize = 4096;
/// Code, identifier, length and authenticator.
pub const HEADER_LEN: usize = 20;
/// The value of one attribute is at most this long (its length octet counts the 2-octet header).
pub const MAX_ATTRIBUTE_LEN: usize = 253;
/// RFC 2865 §5.2: User-Password is at most 128 octets.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Packet codes this client sends or accepts.
pub mod code {
    pub const ACCESS_REQUEST: u8 = 1;
    pub const ACCESS_ACCEPT: u8 = 2;
    pub const ACCESS_REJECT: u8 = 3;
    pub const ACCESS_CHALLENGE: u8 = 11;
}

/// Attribute types this client sends or reads.
pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const STATE: u8 = 24;
    pub const NAS_IDENTIFIER: u8 = 32;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
    pub const NAS_IPV6_ADDRESS: u8 = 95;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("packet is shorter than its header")]
    TooShort,
    #[error("packet is longer than {MAX_PACKET_LEN} bytes")]
    TooLong,
    #[error("the length field does not match the packet")]
    BadLength,
    #[error("malformed attribute")]
    BadAttribute,
    #[error("attribute value is too long")]
    AttributeTooLong,
    #[error("password is too long or contains a NUL byte")]
    BadPassword,
    #[error("unexpected packet code {0}")]
    UnexpectedCode(u8),
    #[error("the response is for another request")]
    WrongIdentifier,
    #[error("the response has no Message-Authenticator")]
    MissingMessageAuthenticator,
    #[error("the response has more than one Message-Authenticator or State")]
    DuplicateAttribute,
    #[error("the Message-Authenticator is not valid")]
    BadMessageAuthenticator,
    #[error("the Response Authenticator is not valid")]
    BadResponseAuthenticator,
}

/// One attribute: type and raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub kind: u8,
    pub value: Vec<u8>,
}

/// A decoded packet. The authenticator is kept as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<Attribute>,
}

impl Packet {
    /// Encodes the packet as it is (no authenticator is computed).
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.push(self.code);
        out.push(self.identifier);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.authenticator);
        for attribute in &self.attributes {
            if attribute.value.len() > MAX_ATTRIBUTE_LEN {
                return Err(PacketError::AttributeTooLong);
            }
            out.push(attribute.kind);
            // Checked above: at most 255.
            out.push((attribute.value.len() + 2) as u8);
            out.extend_from_slice(&attribute.value);
        }
        if out.len() > MAX_PACKET_LEN {
            return Err(PacketError::TooLong);
        }
        let len = (out.len() as u16).to_be_bytes();
        out[2..4].copy_from_slice(&len);
        Ok(out)
    }

    /// Decodes a packet. Octets past the length field are padding and are ignored
    /// (RFC 2865 §3); a packet shorter than its length field is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::TooShort);
        }
        if bytes.len() > MAX_PACKET_LEN {
            return Err(PacketError::TooLong);
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&length) || length > bytes.len() {
            return Err(PacketError::BadLength);
        }
        let mut authenticator = [0; 16];
        authenticator.copy_from_slice(&bytes[4..HEADER_LEN]);
        let mut attributes = Vec::new();
        let mut rest = &bytes[HEADER_LEN..length];
        while !rest.is_empty() {
            if rest.len() < 2 {
                return Err(PacketError::BadAttribute);
            }
            let attribute_len = usize::from(rest[1]);
            if attribute_len < 2 || attribute_len > rest.len() {
                return Err(PacketError::BadAttribute);
            }
            attributes.push(Attribute {
                kind: rest[0],
                value: rest[2..attribute_len].to_vec(),
            });
            rest = &rest[attribute_len..];
        }
        Ok(Self {
            code: bytes[0],
            identifier: bytes[1],
            authenticator,
            attributes,
        })
    }

    fn values(&self, kind: u8) -> impl Iterator<Item = &[u8]> {
        self.attributes
            .iter()
            .filter(move |attribute| attribute.kind == kind)
            .map(|attribute| attribute.value.as_slice())
    }
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hmac_md5(secret: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RFC 2865 §5.2 User-Password hiding. The password is padded with NULs to a multiple of 16
/// octets (at least 16, so an empty password is sent as 16 NULs).
pub fn encrypt_password(
    password: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Result<Vec<u8>, PacketError> {
    if password.len() > MAX_PASSWORD_LEN || password.contains(&0) {
        return Err(PacketError::BadPassword);
    }
    let padded_len = password.len().div_ceil(16).max(1) * 16;
    let mut out = password.to_vec();
    out.resize(padded_len, 0);
    let mut previous: [u8; 16] = *authenticator;
    for chunk in out.chunks_mut(16) {
        let key = md5(&[secret, &previous]);
        for (byte, key_byte) in chunk.iter_mut().zip(key) {
            *byte ^= key_byte;
        }
        previous.copy_from_slice(chunk);
    }
    Ok(out)
}

/// The inverse of [`encrypt_password`], with the padding removed. Used by the test server.
pub fn decrypt_password(
    hidden: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Result<Vec<u8>, PacketError> {
    if hidden.is_empty() || !hidden.len().is_multiple_of(16) || hidden.len() > MAX_PASSWORD_LEN {
        return Err(PacketError::BadPassword);
    }
    let mut out = Vec::with_capacity(hidden.len());
    let mut previous: &[u8] = authenticator;
    for chunk in hidden.chunks(16) {
        let key = md5(&[secret, previous]);
        out.extend(
            chunk
                .iter()
                .zip(key)
                .map(|(byte, key_byte)| byte ^ key_byte),
        );
        previous = chunk;
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    Ok(out)
}

/// What goes into an Access-Request.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    pub user_name: &'a str,
    pub password: &'a [u8],
    pub nas_identifier: &'a str,
    pub nas_ip_address: Option<std::net::IpAddr>,
    /// The State of the Access-Challenge being answered.
    pub state: Option<&'a [u8]>,
}

/// Builds a signed Access-Request: Message-Authenticator first (so that it is covered before any
/// attacker-influenced attribute), then User-Name, User-Password, NAS-Identifier, the NAS address
/// and State.
pub fn build_access_request(
    request: &AccessRequest<'_>,
    identifier: u8,
    authenticator: [u8; 16],
    secret: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let mut attributes = vec![
        Attribute {
            kind: attr::MESSAGE_AUTHENTICATOR,
            value: vec![0; 16],
        },
        Attribute {
            kind: attr::USER_NAME,
            value: request.user_name.as_bytes().to_vec(),
        },
        Attribute {
            kind: attr::USER_PASSWORD,
            value: encrypt_password(request.password, secret, &authenticator)?,
        },
    ];
    if !request.nas_identifier.is_empty() {
        attributes.push(Attribute {
            kind: attr::NAS_IDENTIFIER,
            value: request.nas_identifier.as_bytes().to_vec(),
        });
    }
    match request.nas_ip_address {
        Some(std::net::IpAddr::V4(ip)) => attributes.push(Attribute {
            kind: attr::NAS_IP_ADDRESS,
            value: ip.octets().to_vec(),
        }),
        Some(std::net::IpAddr::V6(ip)) => attributes.push(Attribute {
            kind: attr::NAS_IPV6_ADDRESS,
            value: ip.octets().to_vec(),
        }),
        None => {}
    }
    if let Some(state) = request.state {
        attributes.push(Attribute {
            kind: attr::STATE,
            value: state.to_vec(),
        });
    }
    if request.user_name.is_empty() {
        return Err(PacketError::BadAttribute);
    }
    let mut bytes = Packet {
        code: code::ACCESS_REQUEST,
        identifier,
        authenticator,
        attributes,
    }
    .encode()?;
    // The Message-Authenticator value starts right after the header and its own 2-octet header.
    let mac = hmac_md5(secret, &bytes);
    bytes[HEADER_LEN + 2..HEADER_LEN + 18].copy_from_slice(&mac);
    Ok(bytes)
}

/// The offset of the single Message-Authenticator value in `bytes`, which is a well-formed
/// packet.
fn message_authenticator_offset(bytes: &[u8]) -> Result<usize, PacketError> {
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let mut offset = HEADER_LEN;
    let mut found = None;
    while offset < length {
        let attribute_len = usize::from(bytes[offset + 1]);
        if bytes[offset] == attr::MESSAGE_AUTHENTICATOR {
            if attribute_len != 18 || found.is_some() {
                return Err(if found.is_some() {
                    PacketError::DuplicateAttribute
                } else {
                    PacketError::BadMessageAuthenticator
                });
            }
            found = Some(offset + 2);
        }
        offset += attribute_len;
    }
    found.ok_or(PacketError::MissingMessageAuthenticator)
}

/// What the server decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
    Challenge,
}

/// A verified response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub decision: Decision,
    /// The Reply-Message attributes, joined with new lines, as sent (not yet sanitized).
    pub reply_message: Option<Vec<u8>>,
    pub state: Option<Vec<u8>>,
}

/// Checks a response to the request with `identifier` and `request_authenticator`.
///
/// In this order: the packet is well formed; its code is Accept, Reject or Challenge; it answers
/// this request; it carries exactly one valid Message-Authenticator (HMAC-MD5 over the packet with
/// the Request Authenticator in place of the Response Authenticator, RFC 3579 §3.2); and its
/// Response Authenticator is valid (RFC 2865 §3). A response failing any check is refused, so a
/// forged or tampered answer can never be taken for an Accept.
pub fn verify_response(
    bytes: &[u8],
    identifier: u8,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> Result<Response, PacketError> {
    let packet = Packet::decode(bytes)?;
    let decision = match packet.code {
        code::ACCESS_ACCEPT => Decision::Accept,
        code::ACCESS_REJECT => Decision::Reject,
        code::ACCESS_CHALLENGE => Decision::Challenge,
        other => return Err(PacketError::UnexpectedCode(other)),
    };
    if packet.identifier != identifier {
        return Err(PacketError::WrongIdentifier);
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let bytes = &bytes[..length];

    let mac_offset = message_authenticator_offset(bytes)?;
    let mut signed = bytes.to_vec();
    signed[4..HEADER_LEN].copy_from_slice(request_authenticator);
    signed[mac_offset..mac_offset + 16].fill(0);
    let expected_mac = hmac_md5(secret, &signed);
    if !constant_time_eq(&expected_mac, &bytes[mac_offset..mac_offset + 16]) {
        return Err(PacketError::BadMessageAuthenticator);
    }

    let expected_authenticator = md5(&[
        &bytes[..4],
        request_authenticator,
        &bytes[HEADER_LEN..],
        secret,
    ]);
    if !constant_time_eq(&expected_authenticator, &packet.authenticator) {
        return Err(PacketError::BadResponseAuthenticator);
    }

    let mut states = packet.values(attr::STATE);
    let state = states.next().map(<[u8]>::to_vec);
    if states.next().is_some() {
        return Err(PacketError::DuplicateAttribute);
    }
    let messages: Vec<&[u8]> = packet.values(attr::REPLY_MESSAGE).collect();
    let reply_message = (!messages.is_empty()).then(|| messages.join(&b'\n'));
    Ok(Response {
        decision,
        reply_message,
        state,
    })
}

/// Builds a signed response, as a RADIUS server does. For the test server and tests.
pub fn build_response(
    response_code: u8,
    identifier: u8,
    request_authenticator: &[u8; 16],
    secret: &[u8],
    mut attributes: Vec<Attribute>,
    with_message_authenticator: bool,
) -> Result<Vec<u8>, PacketError> {
    if with_message_authenticator {
        attributes.insert(
            0,
            Attribute {
                kind: attr::MESSAGE_AUTHENTICATOR,
                value: vec![0; 16],
            },
        );
    }
    let mut bytes = Packet {
        code: response_code,
        identifier,
        authenticator: *request_authenticator,
        attributes,
    }
    .encode()?;
    if with_message_authenticator {
        let mac = hmac_md5(secret, &bytes);
        bytes[HEADER_LEN + 2..HEADER_LEN + 18].copy_from_slice(&mac);
    }
    let authenticator = md5(&[&bytes, secret]);
    bytes[4..HEADER_LEN].copy_from_slice(&authenticator);
    Ok(bytes)
}

/// Checks the Message-Authenticator of an Access-Request. For the test server.
pub fn verify_request(bytes: &[u8], secret: &[u8]) -> Result<Packet, PacketError> {
    let packet = Packet::decode(bytes)?;
    if packet.code != code::ACCESS_REQUEST {
        return Err(PacketError::UnexpectedCode(packet.code));
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let bytes = &bytes[..length];
    let mac_offset = message_authenticator_offset(bytes)?;
    let mut signed = bytes.to_vec();
    signed[mac_offset..mac_offset + 16].fill(0);
    if !constant_time_eq(
        &hmac_md5(secret, &signed),
        &bytes[mac_offset..mac_offset + 16],
    ) {
        return Err(PacketError::BadMessageAuthenticator);
    }
    Ok(packet)
}

#[cfg(test)]
mod tests;
