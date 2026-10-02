//! Bridge message layout v1 (spec §4.4). Fixed big-endian fields, no padding,
//! no length prefixes: every kind has one exact length.

use alloc::vec::Vec;

pub const MESSAGE_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 18;
pub const CREDENTIAL_STATUS_BODY_LEN: usize = 138;
pub const ISSUER_STATUS_BODY_LEN: usize = 33;
pub const HEARTBEAT_BODY_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageKind {
    CredentialStatus = 0x01,
    IssuerStatus = 0x02,
    Heartbeat = 0x03,
}

impl MessageKind {
    pub fn from_u8(v: u8) -> Result<Self, CodecError> {
        match v {
            0x01 => Ok(Self::CredentialStatus),
            0x02 => Ok(Self::IssuerStatus),
            0x03 => Ok(Self::Heartbeat),
            other => Err(CodecError::UnknownKind(other)),
        }
    }

    fn body_len(self) -> usize {
        match self {
            Self::CredentialStatus => CREDENTIAL_STATUS_BODY_LEN,
            Self::IssuerStatus => ISSUER_STATUS_BODY_LEN,
            Self::Heartbeat => HEARTBEAT_BODY_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExportStatus {
    Active = 1,
    Revoked = 2,
    Expired = 3,
    Unbound = 4,
}

impl ExportStatus {
    pub fn from_u8(v: u8) -> Result<Self, CodecError> {
        match v {
            1 => Ok(Self::Active),
            2 => Ok(Self::Revoked),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Unbound),
            other => Err(CodecError::BadStatus(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kind: MessageKind,
    pub domain_seq: u64,
    pub solidus_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStatusBody {
    pub export_id: [u8; 32],
    pub issuer_did_hash: [u8; 32],
    pub credential_type_hash: [u8; 32],
    pub holder: [u8; 32],
    pub status: ExportStatus,
    pub valid_until: u64,
    pub issuer_accredited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerStatusBody {
    pub issuer_did_hash: [u8; 32],
    pub accredited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatBody {
    pub solidus_timestamp: u64,
    pub global_root: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMessage {
    CredentialStatus {
        header: Header,
        body: CredentialStatusBody,
    },
    IssuerStatus {
        header: Header,
        body: IssuerStatusBody,
    },
    Heartbeat {
        header: Header,
        body: HeartbeatBody,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    BadVersion(u8),
    UnknownKind(u8),
    BadLength { expected: usize, got: usize },
    BadStatus(u8),
    BadBool(u8),
}

impl BridgeMessage {
    pub fn credential_status(
        domain_seq: u64,
        solidus_height: u64,
        body: CredentialStatusBody,
    ) -> Self {
        Self::CredentialStatus {
            header: header(MessageKind::CredentialStatus, domain_seq, solidus_height),
            body,
        }
    }

    pub fn issuer_status(domain_seq: u64, solidus_height: u64, body: IssuerStatusBody) -> Self {
        Self::IssuerStatus {
            header: header(MessageKind::IssuerStatus, domain_seq, solidus_height),
            body,
        }
    }

    pub fn heartbeat(domain_seq: u64, solidus_height: u64, body: HeartbeatBody) -> Self {
        Self::Heartbeat {
            header: header(MessageKind::Heartbeat, domain_seq, solidus_height),
            body,
        }
    }

    pub fn header(&self) -> &Header {
        match self {
            Self::CredentialStatus { header, .. }
            | Self::IssuerStatus { header, .. }
            | Self::Heartbeat { header, .. } => header,
        }
    }
}

fn header(kind: MessageKind, domain_seq: u64, solidus_height: u64) -> Header {
    Header {
        version: MESSAGE_VERSION,
        kind,
        domain_seq,
        solidus_height,
    }
}

/// Encode a message. The kind byte comes from the VARIANT, so a caller cannot
/// produce a CredentialStatus body labelled as a Heartbeat.
pub fn encode(msg: &BridgeMessage) -> Vec<u8> {
    let h = msg.header();
    let kind = match msg {
        BridgeMessage::CredentialStatus { .. } => MessageKind::CredentialStatus,
        BridgeMessage::IssuerStatus { .. } => MessageKind::IssuerStatus,
        BridgeMessage::Heartbeat { .. } => MessageKind::Heartbeat,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + kind.body_len());
    out.push(MESSAGE_VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&h.domain_seq.to_be_bytes());
    out.extend_from_slice(&h.solidus_height.to_be_bytes());
    match msg {
        BridgeMessage::CredentialStatus { body, .. } => {
            out.extend_from_slice(&body.export_id);
            out.extend_from_slice(&body.issuer_did_hash);
            out.extend_from_slice(&body.credential_type_hash);
            out.extend_from_slice(&body.holder);
            out.push(body.status as u8);
            out.extend_from_slice(&body.valid_until.to_be_bytes());
            out.push(u8::from(body.issuer_accredited));
        }
        BridgeMessage::IssuerStatus { body, .. } => {
            out.extend_from_slice(&body.issuer_did_hash);
            out.push(u8::from(body.accredited));
        }
        BridgeMessage::Heartbeat { body, .. } => {
            out.extend_from_slice(&body.solidus_timestamp.to_be_bytes());
            out.extend_from_slice(&body.global_root);
        }
    }
    out
}

/// Decode untrusted bytes. Every check happens before the field it guards is read.
pub fn decode(bytes: &[u8]) -> Result<BridgeMessage, CodecError> {
    if bytes.len() < HEADER_LEN {
        return Err(CodecError::BadLength {
            expected: HEADER_LEN,
            got: bytes.len(),
        });
    }
    if bytes[0] != MESSAGE_VERSION {
        return Err(CodecError::BadVersion(bytes[0]));
    }
    let kind = MessageKind::from_u8(bytes[1])?;
    let expected = HEADER_LEN + kind.body_len();
    if bytes.len() != expected {
        return Err(CodecError::BadLength {
            expected,
            got: bytes.len(),
        });
    }
    let hdr = header(kind, be_u64(&bytes[2..10]), be_u64(&bytes[10..18]));
    let b = &bytes[HEADER_LEN..];
    Ok(match kind {
        MessageKind::CredentialStatus => BridgeMessage::CredentialStatus {
            header: hdr,
            body: CredentialStatusBody {
                export_id: arr32(&b[0..32]),
                issuer_did_hash: arr32(&b[32..64]),
                credential_type_hash: arr32(&b[64..96]),
                holder: arr32(&b[96..128]),
                status: ExportStatus::from_u8(b[128])?,
                valid_until: be_u64(&b[129..137]),
                issuer_accredited: bool_byte(b[137])?,
            },
        },
        MessageKind::IssuerStatus => BridgeMessage::IssuerStatus {
            header: hdr,
            body: IssuerStatusBody {
                issuer_did_hash: arr32(&b[0..32]),
                accredited: bool_byte(b[32])?,
            },
        },
        MessageKind::Heartbeat => BridgeMessage::Heartbeat {
            header: hdr,
            body: HeartbeatBody {
                solidus_timestamp: be_u64(&b[0..8]),
                global_root: arr32(&b[8..40]),
            },
        },
    })
}

pub(crate) fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

pub(crate) fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&b[..32]);
    a
}

pub(crate) fn bool_byte(v: u8) -> Result<bool, CodecError> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(CodecError::BadBool(other)),
    }
}
