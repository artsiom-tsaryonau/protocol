use solidus_bridge_codec::{
    decode, encode, BridgeMessage, CodecError, CredentialStatusBody, ExportStatus, HeartbeatBody,
    IssuerStatusBody, MessageKind, HEADER_LEN, MESSAGE_VERSION,
};

fn credential_body(status: ExportStatus) -> CredentialStatusBody {
    CredentialStatusBody {
        export_id: [0x01; 32],
        issuer_did_hash: [0x02; 32],
        credential_type_hash: [0x03; 32],
        holder: [0x04; 32],
        status,
        valid_until: 1_900_000_000,
        issuer_accredited: true,
    }
}

#[test]
fn credential_status_encodes_to_156_bytes_with_a_big_endian_header() {
    let msg = BridgeMessage::credential_status(7, 1234, credential_body(ExportStatus::Active));
    let bytes = encode(&msg);
    assert_eq!(bytes.len(), 156);
    assert_eq!(bytes[0], MESSAGE_VERSION);
    assert_eq!(bytes[1], MessageKind::CredentialStatus as u8);
    assert_eq!(&bytes[2..10], &7u64.to_be_bytes());
    assert_eq!(&bytes[10..18], &1234u64.to_be_bytes());
    assert_eq!(&bytes[18..50], &[0x01; 32]);
    assert_eq!(bytes[146], ExportStatus::Active as u8);
    assert_eq!(&bytes[147..155], &1_900_000_000u64.to_be_bytes());
    assert_eq!(bytes[155], 1);
}

#[test]
fn every_kind_round_trips() {
    let cases = [
        BridgeMessage::credential_status(1, 2, credential_body(ExportStatus::Revoked)),
        BridgeMessage::issuer_status(
            u64::MAX,
            u64::MAX,
            IssuerStatusBody {
                issuer_did_hash: [9; 32],
                accredited: false,
            },
        ),
        BridgeMessage::heartbeat(
            3,
            0,
            HeartbeatBody {
                solidus_timestamp: 1_758_000_000,
                global_root: [0xAB; 32],
            },
        ),
    ];
    for msg in cases {
        assert_eq!(decode(&encode(&msg)).expect("round trip"), msg);
    }
}

#[test]
fn issuer_status_is_51_bytes_and_heartbeat_is_58() {
    let i = BridgeMessage::issuer_status(
        1,
        1,
        IssuerStatusBody {
            issuer_did_hash: [0; 32],
            accredited: true,
        },
    );
    let h = BridgeMessage::heartbeat(
        1,
        1,
        HeartbeatBody {
            solidus_timestamp: 1,
            global_root: [0; 32],
        },
    );
    assert_eq!(encode(&i).len(), 51);
    assert_eq!(encode(&h).len(), 58);
    assert_eq!(HEADER_LEN, 18);
}

#[test]
fn decode_rejects_short_input_before_reading_anything() {
    assert_eq!(
        decode(&[]),
        Err(CodecError::BadLength {
            expected: 18,
            got: 0
        })
    );
    assert_eq!(
        decode(&[1u8; 17]),
        Err(CodecError::BadLength {
            expected: 18,
            got: 17
        })
    );
}

#[test]
fn decode_rejects_an_unknown_version() {
    let mut bytes = encode(&BridgeMessage::heartbeat(
        1,
        1,
        HeartbeatBody {
            solidus_timestamp: 1,
            global_root: [0; 32],
        },
    ));
    bytes[0] = 2;
    assert_eq!(decode(&bytes), Err(CodecError::BadVersion(2)));
}

#[test]
fn decode_rejects_an_unknown_kind() {
    let mut bytes = encode(&BridgeMessage::heartbeat(
        1,
        1,
        HeartbeatBody {
            solidus_timestamp: 1,
            global_root: [0; 32],
        },
    ));
    bytes[1] = 0x09;
    assert_eq!(decode(&bytes), Err(CodecError::UnknownKind(0x09)));
}

#[test]
fn decode_rejects_a_body_one_byte_short_or_long() {
    let bytes = encode(&BridgeMessage::credential_status(
        1,
        1,
        credential_body(ExportStatus::Active),
    ));
    assert_eq!(
        decode(&bytes[..155]),
        Err(CodecError::BadLength {
            expected: 156,
            got: 155
        })
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        decode(&long),
        Err(CodecError::BadLength {
            expected: 156,
            got: 157
        })
    );
}

#[test]
fn decode_rejects_an_out_of_range_status_and_a_non_boolean_flag() {
    let mut bytes = encode(&BridgeMessage::credential_status(
        1,
        1,
        credential_body(ExportStatus::Active),
    ));
    bytes[146] = 5;
    assert_eq!(decode(&bytes), Err(CodecError::BadStatus(5)));
    bytes[146] = 0;
    assert_eq!(decode(&bytes), Err(CodecError::BadStatus(0)));
    bytes[146] = 1;
    bytes[155] = 2;
    assert_eq!(decode(&bytes), Err(CodecError::BadBool(2)));
}
