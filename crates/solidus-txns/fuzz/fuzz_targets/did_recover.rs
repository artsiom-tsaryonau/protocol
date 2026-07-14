#![no_main]
use libfuzzer_sys::fuzz_target;
use solidus_txns::types::TxPayload;

fuzz_target!(|data: &[u8]| {
    // Deserializing untrusted bytes must never panic.
    let _ = serde_json::from_slice::<TxPayload>(data);
});
