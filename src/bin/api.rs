//! Minimal REST API wrapping the Kaspa Escrow SDK.
//!
//! Usage:
//!   cargo run --bin api
//!
//! Requires:
//!   - kaspad running with --rpclisten-borsh=127.0.0.1:17110 --utxoindex

use kaspa_escrow_lab::api::{AppState, build_router};
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to kaspad at ws://127.0.0.1:17110...");

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;
    client.connect(None).await.map_err(|e| {
        format!(
            "Failed to connect: {e}\n  \
             Is kaspad running with --rpclisten-borsh=127.0.0.1:17110?"
        )
    })?;

    let info = client.get_block_dag_info().await?;
    println!(
        "Connected! Network: {}, DAA: {}",
        info.network, info.virtual_daa_score
    );

    let state = AppState {
        client: Arc::new(client),
        escrows: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://0.0.0.0:3000");
    println!();
    println!("Endpoints:");
    println!("  POST /escrow              Create escrow");
    println!("  GET  /escrow/{{id}}         Status + details");
    println!("  POST /escrow/{{id}}/fund    Lock funds into P2SH");
    println!("  POST /escrow/{{id}}/release Release to seller");
    println!("  POST /escrow/{{id}}/refund  Timeout refund to buyer");
    println!("  POST /escrow/{{id}}/dispute Arbitrated dispute");
    println!("  GET  /escrow/{{id}}/script  Disassemble redeem script");

    axum::serve(listener, app).await?;

    Ok(())
}
