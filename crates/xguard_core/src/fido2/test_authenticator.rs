//! A software CTAP2 authenticator with a P-256 key, for tests.
//!
//! It produces exactly what the desktop client sends: a "none" attestation built from the key's
//! authenticator data on registration, and raw authenticator data plus a DER ECDSA signature over
//! `authenticatorData || SHA-256(canonical client data)` on assertion.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};

use super::{ClientDataType, Fido2Assertion, client_data_json};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;

fn sha256(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::sha256(), data)
        .expect("SHA-256")
        .to_vec()
}

/// CBOR major type with a length argument.
fn cbor_head(major: u8, len: usize) -> Vec<u8> {
    let major = major << 5;
    match len {
        0..=23 => vec![major | len as u8],
        24..=0xff => vec![major | 24, len as u8],
        _ => {
            let len = u16::try_from(len).expect("short CBOR item");
            let [hi, lo] = len.to_be_bytes();
            vec![major | 25, hi, lo]
        }
    }
}

fn cbor_text(text: &str) -> Vec<u8> {
    let mut out = cbor_head(3, text.len());
    out.extend_from_slice(text.as_bytes());
    out
}

fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, data.len());
    out.extend_from_slice(data);
    out
}

/// A software security key holding one P-256 credential.
pub struct TestAuthenticator {
    key: PKey<Private>,
    x: Vec<u8>,
    y: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    /// Report user verification (a PIN was entered).
    pub user_verified: bool,
    /// Report the credential as backup eligible, like a synced passkey.
    pub backup_eligible: bool,
}

impl Default for TestAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAuthenticator {
    #[must_use]
    pub fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
        let ec = EcKey::generate(&group).expect("P-256 key");
        let mut ctx = BigNumContext::new().expect("bignum context");
        let mut x = BigNum::new().expect("bignum");
        let mut y = BigNum::new().expect("bignum");
        ec.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .expect("public key coordinates");
        let mut credential_id = vec![0u8; 32];
        openssl::rand::rand_bytes(&mut credential_id).expect("random credential ID");
        Self {
            x: x.to_vec_padded(32).expect("x coordinate"),
            y: y.to_vec_padded(32).expect("y coordinate"),
            key: PKey::from_ec_key(ec).expect("private key"),
            credential_id,
            counter: 0,
            user_verified: true,
            backup_eligible: false,
        }
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut flags = FLAG_UP;
        if self.user_verified {
            flags |= FLAG_UV;
        }
        if self.backup_eligible {
            flags |= FLAG_BE;
        }
        if attested {
            flags |= FLAG_AT;
        }
        flags
    }

    fn cose_key(&self) -> Vec<u8> {
        // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
        let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        out.extend(cbor_bytes(&self.x));
        out.push(0x22);
        out.extend(cbor_bytes(&self.y));
        out
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).expect("signer");
        signer.update(data).expect("sign");
        signer.sign_to_vec().expect("signature")
    }

    /// Answers WebAuthn creation options (JSON, as Core sends them) with a registration response
    /// (JSON, as the client sends it back).
    ///
    /// # Panics
    /// On creation options without a relying party ID or challenge.
    #[must_use]
    pub fn register(&mut self, creation_options: &str, origin: &str) -> String {
        let options: serde_json::Value =
            serde_json::from_str(creation_options).expect("creation options");
        let rp_id = options["publicKey"]["rp"]["id"]
            .as_str()
            .expect("relying party ID");
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .expect("challenge");
        let client_data = client_data_json(ClientDataType::Create, challenge, origin);

        let mut auth_data = sha256(rp_id.as_bytes());
        auth_data.push(self.flags(true));
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        let id_len = u16::try_from(self.credential_id.len()).expect("credential ID length");
        auth_data.extend_from_slice(&id_len.to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend(self.cose_key());

        let mut attestation_object = vec![0xa3];
        attestation_object.extend(cbor_text("fmt"));
        attestation_object.extend(cbor_text("none"));
        attestation_object.extend(cbor_text("attStmt"));
        attestation_object.push(0xa0);
        attestation_object.extend(cbor_text("authData"));
        attestation_object.extend(cbor_bytes(&auth_data));

        let id = URL_SAFE_NO_PAD.encode(&self.credential_id);
        serde_json::json!({
            "id": id,
            "rawId": id,
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation_object),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
            },
            "type": "public-key",
            "extensions": {},
        })
        .to_string()
    }

    /// Signs `client_data` (already canonical) for `rp_id`, advancing the counter.
    #[must_use]
    pub fn assert_client_data(&mut self, rp_id: &str, client_data: &[u8]) -> Fido2Assertion {
        self.counter += 1;
        self.assert_client_data_with_counter(rp_id, client_data, self.counter)
    }

    /// As [`Self::assert_client_data`], with an explicit counter (for clone tests).
    #[must_use]
    pub fn assert_client_data_with_counter(
        &self,
        rp_id: &str,
        client_data: &[u8],
        counter: u32,
    ) -> Fido2Assertion {
        let mut auth_data = sha256(rp_id.as_bytes());
        auth_data.push(self.flags(false));
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend(sha256(client_data));
        Fido2Assertion {
            rp_id_hash: auth_data[..32].to_vec(),
            signature: self.sign(&signed),
            authenticator_data: auth_data,
            credential_id: self.credential_id.clone(),
        }
    }

    /// Answers an assertion challenge the way the desktop client does.
    #[must_use]
    pub fn assert(&mut self, rp_id: &str, challenge: &str, origin: &str) -> Fido2Assertion {
        let client_data = client_data_json(ClientDataType::Get, challenge, origin);
        self.assert_client_data(rp_id, &client_data)
    }
}
