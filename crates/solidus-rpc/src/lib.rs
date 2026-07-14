// Production hardening: forbid panic-via-unwrap/expect outside tests.
// solidus-rpc has zero non-test unwrap/expect sites today (this lint enforces
// going forward).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

pub mod methods;
pub mod server;
pub mod types;
