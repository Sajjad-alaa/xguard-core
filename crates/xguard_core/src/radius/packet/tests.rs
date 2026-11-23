use super::*;

#[test]
fn password_hiding_matches_rfc2865_vector_and_roundtrips() {
    let secret = b"testing123";
    let auth = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    for password in [
        &b""[..],
        &b"123456"[..],
        &b"exactly16bytes!!"[..],
        &b"more-than-sixteen-bytes-password-value"[..],
    ] {
        let hidden = encrypt_password(password, secret, &auth).unwrap();
        assert_eq!(hidden.len() % 16, 0);
        assert!(hidden.len() >= 16);
        let plain = decrypt_password(&hidden, secret, &auth).unwrap();
        assert_eq!(plain, password);
    }

    // Empty password must produce 16 bytes (16 NULs XOR MD5(secret || auth)).
    let empty_hidden = encrypt_password(b"", secret, &auth).unwrap();
    assert_eq!(empty_hidden, md5(&[secret, &auth]));
}

#[test]
fn password_rejects_nul_and_too_long() {
    let auth = [7u8; 16];
    assert_eq!(
        encrypt_password(b"abc\0def", b"secret", &auth),
        Err(PacketError::BadPassword)
    );
    let long = vec![b'a'; MAX_PASSWORD_LEN + 1];
    assert_eq!(
        encrypt_password(&long, b"secret", &auth),
        Err(PacketError::BadPassword)
    );
}

#[test]
fn build_access_request_signs_message_authenticator_first() {
    let secret = b"super-shared-secret";
    let auth = [0x42u8; 16];
    let req = AccessRequest {
        user_name: "alice",
        password: b"654321",
        nas_identifier: "xguard",
        nas_ip_address: Some("10.0.0.1".parse().unwrap()),
        state: Some(b"opaque-state"),
    };
    let bytes = build_access_request(&req, 9, auth, secret).unwrap();
    let packet = verify_request(&bytes, secret).unwrap();
    assert_eq!(packet.code, code::ACCESS_REQUEST);
    assert_eq!(packet.identifier, 9);
    assert_eq!(packet.attributes[0].kind, attr::MESSAGE_AUTHENTICATOR);
    assert_eq!(packet.values(attr::USER_NAME).next(), Some(&b"alice"[..]));
    assert_eq!(
        packet.values(attr::NAS_IDENTIFIER).next(),
        Some(&b"xguard"[..])
    );
    assert_eq!(
        packet.values(attr::STATE).next(),
        Some(&b"opaque-state"[..])
    );
    let hidden = packet.values(attr::USER_PASSWORD).next().unwrap();
    assert_eq!(decrypt_password(hidden, secret, &auth).unwrap(), b"654321");

    // Wrong secret fails verification.
    assert_eq!(
        verify_request(&bytes, b"wrong-secret"),
        Err(PacketError::BadMessageAuthenticator)
    );
}

#[test]
fn verify_response_enforces_blastradius_and_authenticators() {
    let secret = b"radius-secret";
    let auth = [0x11u8; 16];
    let id = 42;

    // Valid signed Access-Challenge with State and Reply-Message.
    let valid = build_response(
        code::ACCESS_CHALLENGE,
        id,
        &auth,
        secret,
        vec![
            Attribute {
                kind: attr::REPLY_MESSAGE,
                value: b"Enter SMS code".to_vec(),
            },
            Attribute {
                kind: attr::STATE,
                value: b"state-123".to_vec(),
            },
        ],
        true,
    )
    .unwrap();
    let parsed = verify_response(&valid, id, &auth, secret).unwrap();
    assert_eq!(parsed.decision, Decision::Challenge);
    assert_eq!(
        parsed.reply_message.as_deref(),
        Some(&b"Enter SMS code"[..])
    );
    assert_eq!(parsed.state.as_deref(), Some(&b"state-123"[..]));

    // Missing Message-Authenticator MUST be rejected (BlastRADIUS / CVE-2024-3596).
    let unsigned = build_response(code::ACCESS_ACCEPT, id, &auth, secret, vec![], false).unwrap();
    assert_eq!(
        verify_response(&unsigned, id, &auth, secret),
        Err(PacketError::MissingMessageAuthenticator)
    );

    // Tampered Message-Authenticator MUST be rejected.
    let mut bad_mac = valid.clone();
    bad_mac[HEADER_LEN + 2] ^= 0xFF;
    assert_eq!(
        verify_response(&bad_mac, id, &auth, secret),
        Err(PacketError::BadMessageAuthenticator)
    );

    // Tampered Response Authenticator MUST be rejected.
    let mut bad_auth = valid.clone();
    bad_auth[4] ^= 0xFF;
    assert_eq!(
        verify_response(&bad_auth, id, &auth, secret),
        Err(PacketError::BadResponseAuthenticator)
    );

    // Wrong identifier MUST be rejected.
    assert_eq!(
        verify_response(&valid, id.wrapping_add(1), &auth, secret),
        Err(PacketError::WrongIdentifier)
    );
}
