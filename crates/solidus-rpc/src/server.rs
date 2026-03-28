use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use jsonrpsee::server::{Server, ServerHandle};
use tracing::info;

use solidus_consensus::mempool::Mempool;
use solidus_state::store::Store;

use crate::methods::{SolidusApiServer, SolidusRpcImpl};

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the JSON-RPC server and return a handle + the actual local address.
///
/// The caller should hold onto the [`ServerHandle`] to keep the server running
/// and call `handle.stop()` for a graceful shutdown.
pub async fn start_rpc_server(
    listen_addr: SocketAddr,
    store: Arc<Store>,
    mempool: Arc<Mutex<Mempool>>,
    latest_height: Arc<Mutex<u64>>,
) -> Result<(ServerHandle, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::builder().build(listen_addr).await?;

    let local_addr = server.local_addr()?;
    info!("JSON-RPC server listening on {local_addr}");

    let rpc_impl = SolidusRpcImpl::new(store, mempool, latest_height);
    let handle = server.start(rpc_impl.into_rpc());

    Ok((handle, local_addr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn server_starts_and_stops() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let latest_height = Arc::new(Mutex::new(0u64));

        // Bind to port 0 so the OS picks a random free port.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let (handle, local_addr) = start_rpc_server(addr, store, mempool, latest_height)
            .await
            .expect("server should start");

        assert_ne!(local_addr.port(), 0, "should have a real port");

        // Graceful shutdown.
        handle.stop().expect("server should stop");
    }
}
