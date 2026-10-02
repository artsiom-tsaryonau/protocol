//! Typed reads and writes of bridge records. Bincode, like every v2 record.

use serde::de::DeserializeOwned;
use serde::Serialize;
use solidus_txns::bridge::{BridgeDomain, ExportSet};

use crate::error::ExecError;
use crate::types::StateKey;
use crate::view::TxView;

pub(crate) fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    bincode::serialize(v).expect("bridge record bincode serialization cannot fail")
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ExecError> {
    bincode::deserialize(bytes).map_err(|e| ExecError::StateDecode(e.to_string()))
}

pub(crate) fn read_u64<V: TxView>(view: &mut V, key: &StateKey) -> Result<u64, ExecError> {
    match view.read(key)? {
        None => Ok(0),
        Some(b) => {
            let arr: [u8; 8] = b
                .as_slice()
                .try_into()
                .map_err(|_| ExecError::StateDecode("bridge counter is not 8 bytes".into()))?;
            Ok(u64::from_le_bytes(arr))
        }
    }
}

pub(crate) fn write_u64<V: TxView>(
    view: &mut V,
    key: StateKey,
    value: u64,
) -> Result<(), ExecError> {
    view.write(key, value.to_le_bytes().to_vec())
}

pub(crate) fn load_domain<V: TxView>(
    view: &mut V,
    domain: u32,
) -> Result<Option<BridgeDomain>, ExecError> {
    view.read(&StateKey::bridge_domain(domain))?
        .map(|b| decode(&b))
        .transpose()
}

pub(crate) fn save_domain<V: TxView>(view: &mut V, d: &BridgeDomain) -> Result<(), ExecError> {
    view.write(StateKey::bridge_domain(d.domain), encode(d))
}

pub(crate) fn load_domains_index<V: TxView>(view: &mut V) -> Result<Vec<u32>, ExecError> {
    Ok(view
        .read(&StateKey::bridge_domains_index())?
        .map(|b| decode(&b))
        .transpose()?
        .unwrap_or_default())
}

pub(crate) fn save_domains_index<V: TxView>(
    view: &mut V,
    domains: &[u32],
) -> Result<(), ExecError> {
    view.write(StateKey::bridge_domains_index(), encode(&domains.to_vec()))
}

pub(crate) fn load_exports<V: TxView>(
    view: &mut V,
    credential_id: &str,
) -> Result<ExportSet, ExecError> {
    Ok(view
        .read(&StateKey::bridge_exports(credential_id))?
        .map(|b| decode(&b))
        .transpose()?
        .unwrap_or_default())
}

pub(crate) fn save_exports<V: TxView>(
    view: &mut V,
    credential_id: &str,
    set: &ExportSet,
) -> Result<(), ExecError> {
    view.write(StateKey::bridge_exports(credential_id), encode(set))
}

/// A one-byte flag: `[1]` true, anything else (including absent) false.
pub(crate) fn flag<V: TxView>(view: &mut V, key: &StateKey) -> Result<bool, ExecError> {
    Ok(matches!(view.read(key)?.as_deref(), Some([1])))
}

pub(crate) fn set_flag<V: TxView>(
    view: &mut V,
    key: StateKey,
    value: bool,
) -> Result<(), ExecError> {
    view.write(key, vec![u8::from(value)])
}
