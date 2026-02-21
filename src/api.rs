//! REST API types and router for the Kaspa Escrow SDK.
//!
//! This module contains all the shared types, handlers, and router builder
//! used by the `api` binary and integration tests.

use crate::sdk::{
    Branch, EscrowBuilder, EscrowConfig, EscrowPattern,
    tx::{
        build_dispute_tx, build_funding_tx, build_payment_split_tx, build_refund_tx,
        build_release_tx, build_sig_script,
    },
};
use crate::{
    build_p2pk_sig_script, disassemble_script, generate_keypair, p2pk_spk, schnorr_sign,
    testnet_address, verify_script,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::RpcApi;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// ─── App State ───────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub client: Arc<KaspaRpcClient>,
    pub escrows: Arc<Mutex<HashMap<String, EscrowEntry>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignerMode {
    Custodial,
    External,
}

#[allow(dead_code)] // owner_kp stored for future escape-path endpoint
pub struct EscrowEntry {
    pub id: String,
    pub config: EscrowConfig,
    pub mode: SignerMode,
    pub buyer_kp: Option<secp256k1::Keypair>,
    pub seller_kp: Option<secp256k1::Keypair>,
    pub arbitrator_kp: Option<secp256k1::Keypair>,
    pub owner_kp: Option<secp256k1::Keypair>,
    pub buyer_addr: Address,
    pub funding_tx_id: Option<String>,
    pub funding_outpoint: Option<TransactionOutpoint>,
    pub funding_amount: Option<u64>,
    pub release_tx_id: Option<String>,
    pub refund_tx_id: Option<String>,
    pub dispute_tx_id: Option<String>,
}

// ─── Request / Response DTOs ─────────────────────────────────

#[derive(Deserialize)]
struct CreateEscrowReq {
    pattern: String,
    amount: u64,
    #[serde(default)]
    lock_time: Option<u64>,
    #[serde(default)]
    fee_percent: Option<u64>,
    #[serde(default)]
    buyer_pk: Option<String>,
    #[serde(default)]
    seller_pk: Option<String>,
    #[serde(default)]
    arbitrator_pk: Option<String>,
    #[serde(default)]
    owner_pk: Option<String>,
    #[serde(default)]
    fee_pk: Option<String>,
}

#[derive(Serialize)]
struct EscrowResponse {
    id: String,
    mode: String,
    status: String,
    funding_address: String,
    escrow_amount: u64,
    pattern: String,
    buyer_pk: String,
    seller_pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    arbitrator_pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_pk: Option<String>,
    seller_amount: u64,
    fee_amount: u64,
    redeem_script_hex: String,
}

#[derive(Serialize)]
struct StatusResponse {
    id: String,
    status: String,
    funding_address: String,
    escrow_amount: u64,
    pattern: String,
    buyer_pk: String,
    seller_pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_daa: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    funding_tx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_tx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_tx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dispute_tx_id: Option<String>,
}

#[derive(Deserialize)]
struct FundReq {
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseReq {
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    signatures: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RefundReq {
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct DisputeReq {
    winner: String,
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    signatures: Option<Vec<String>>,
}

#[derive(Serialize)]
struct TxResponse {
    tx_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    winner: Option<String>,
}

#[derive(Serialize)]
struct ScriptResponse {
    redeem_script_hex: String,
    disassembly: String,
    length: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn default_fee() -> u64 {
    5_000
}

// ─── Error helpers ───────────────────────────────────────────

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn conflict(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn internal(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: msg.into() }),
    )
}

type ApiResult<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ErrorResponse>)>;

// ─── Helpers ─────────────────────────────────────────────────

fn parse_hex_pk(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex pubkey: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())
}

fn parse_hex_sig(hex_str: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex signature: {e}"))?;
    if bytes.len() != 65 {
        return Err(format!(
            "signature must be 65 bytes (64-byte schnorr + sighash type), got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn pattern_name(pattern: &EscrowPattern) -> &'static str {
    match pattern {
        EscrowPattern::Basic => "basic",
        EscrowPattern::Arbitrated => "arbitrated",
        EscrowPattern::TimeLocked { .. } => "timelocked",
        EscrowPattern::CovenantMultiPath { .. } => "covenant_multi_path",
        EscrowPattern::PaymentSplit { .. } => "payment_split",
    }
}

fn mode_name(mode: SignerMode) -> &'static str {
    match mode {
        SignerMode::Custodial => "custodial",
        SignerMode::External => "external",
    }
}

/// Compute the escrow status from internal state.
fn compute_status(entry: &EscrowEntry) -> &'static str {
    if entry.release_tx_id.is_some() {
        "released"
    } else if entry.refund_tx_id.is_some() {
        "refunded"
    } else if entry.dispute_tx_id.is_some() {
        "disputed"
    } else if entry.funding_tx_id.is_some() {
        "locked"
    } else {
        "awaiting_funding"
    }
}

/// Query for a mature UTXO at the given address.
async fn find_mature_utxo(
    client: &KaspaRpcClient,
    address: &Address,
) -> Result<Option<(TransactionOutpoint, u64)>, String> {
    let info = client
        .get_block_dag_info()
        .await
        .map_err(|e| format!("RPC error: {e}"))?;
    let current_daa = info.virtual_daa_score;

    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|e| format!("RPC error: {e}"))?;

    let mature = utxos
        .iter()
        .find(|e| !e.utxo_entry.is_coinbase || current_daa >= e.utxo_entry.block_daa_score + 1000);

    Ok(mature.map(|e| {
        let op = TransactionOutpoint::new(e.outpoint.transaction_id, e.outpoint.index);
        (op, e.utxo_entry.amount)
    }))
}

/// Submit a transaction with retry for finalization.
async fn submit_with_retry(
    client: &KaspaRpcClient,
    rpc_tx: RpcTransaction,
) -> Result<String, String> {
    let max_retries = 20;
    for attempt in 1..=max_retries {
        match client.submit_transaction(rpc_tx.clone(), false).await {
            Ok(id) => return Ok(format!("{id}")),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("not finalized") && attempt < max_retries {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
                return Err(format!("TX rejected after {attempt} attempts: {e}"));
            }
        }
    }
    unreachable!()
}

// ─── POST /escrow ────────────────────────────────────────────

async fn create_escrow(
    State(state): State<AppState>,
    Json(req): Json<CreateEscrowReq>,
) -> ApiResult<EscrowResponse> {
    let pattern = match req.pattern.as_str() {
        "basic" => EscrowPattern::Basic,
        "arbitrated" => EscrowPattern::Arbitrated,
        "timelocked" => {
            let lt = req
                .lock_time
                .ok_or_else(|| bad_request("lock_time required for timelocked pattern"))?;
            EscrowPattern::TimeLocked { lock_time: lt }
        }
        "covenant_multi_path" => {
            let lt = req
                .lock_time
                .ok_or_else(|| bad_request("lock_time required for covenant_multi_path pattern"))?;
            EscrowPattern::CovenantMultiPath { lock_time: lt }
        }
        "payment_split" => {
            let fp = req
                .fee_percent
                .ok_or_else(|| bad_request("fee_percent required for payment_split pattern"))?;
            EscrowPattern::PaymentSplit { fee_percent: fp }
        }
        other => return Err(bad_request(format!("unknown pattern: {other}"))),
    };

    // Determine mode: if any pubkey is provided, use external; else custodial.
    // Partial external (only buyer or only seller) creates unresolvable escrows.
    let has_buyer = req.buyer_pk.is_some();
    let has_seller = req.seller_pk.is_some();
    if has_buyer != has_seller {
        return Err(bad_request(
            "provide both buyer_pk and seller_pk for external mode, or neither for custodial",
        ));
    }
    let mode = if has_buyer {
        SignerMode::External
    } else {
        SignerMode::Custodial
    };

    // Resolve keypairs
    let (buyer_kp, buyer_pk) = if let Some(ref hex) = req.buyer_pk {
        let pk = parse_hex_pk(hex).map_err(bad_request)?;
        (None, pk)
    } else {
        let (kp, pk) = generate_keypair();
        (Some(kp), pk)
    };

    let (seller_kp, seller_pk) = if let Some(ref hex) = req.seller_pk {
        let pk = parse_hex_pk(hex).map_err(bad_request)?;
        (None, pk)
    } else {
        let (kp, pk) = generate_keypair();
        (Some(kp), pk)
    };

    let (arb_kp, arb_pk) = if let Some(ref hex) = req.arbitrator_pk {
        let pk = parse_hex_pk(hex).map_err(bad_request)?;
        (None, Some(pk))
    } else if matches!(
        pattern,
        EscrowPattern::Arbitrated | EscrowPattern::CovenantMultiPath { .. }
    ) {
        let (kp, pk) = generate_keypair();
        (Some(kp), Some(pk))
    } else {
        (None, None)
    };

    let (owner_kp, owner_pk) = if let Some(ref hex) = req.owner_pk {
        let pk = parse_hex_pk(hex).map_err(bad_request)?;
        (None, Some(pk))
    } else if matches!(pattern, EscrowPattern::PaymentSplit { .. }) {
        let (kp, pk) = generate_keypair();
        (Some(kp), Some(pk))
    } else {
        (None, None)
    };

    let fee_pk = if let Some(ref hex) = req.fee_pk {
        Some(parse_hex_pk(hex).map_err(bad_request)?)
    } else if matches!(pattern, EscrowPattern::PaymentSplit { .. }) {
        Some(generate_keypair().1)
    } else {
        None
    };

    // Build config
    let mut builder = EscrowBuilder::new(pattern.clone())
        .buyer(buyer_pk)
        .seller(seller_pk)
        .amount(req.amount);
    if let Some(apk) = arb_pk {
        builder = builder.arbitrator(apk);
    }
    if let Some(opk) = owner_pk {
        builder = builder.owner(opk);
    }
    if let Some(fpk) = fee_pk {
        builder = builder.fee_address(fpk);
    }

    let config = builder.build().map_err(|e| bad_request(format!("{e}")))?;

    let id = Uuid::new_v4().to_string();
    let buyer_addr = testnet_address(&buyer_pk);
    let funding_address = format!("{}", buyer_addr);

    let resp = EscrowResponse {
        id: id.clone(),
        mode: mode_name(mode).to_string(),
        status: "awaiting_funding".to_string(),
        funding_address: funding_address.clone(),
        escrow_amount: config.escrow_amount,
        pattern: pattern_name(&config.pattern).to_string(),
        buyer_pk: hex::encode(config.buyer_pk),
        seller_pk: hex::encode(config.seller_pk),
        arbitrator_pk: config.arbitrator_pk.map(hex::encode),
        owner_pk: config.owner_pk.map(hex::encode),
        fee_pk: config.fee_pk.map(hex::encode),
        seller_amount: config.seller_amount,
        fee_amount: config.fee_amount,
        redeem_script_hex: hex::encode(&config.redeem_script),
    };

    let entry = EscrowEntry {
        id: id.clone(),
        config,
        mode,
        buyer_kp,
        seller_kp,
        arbitrator_kp: arb_kp,
        owner_kp,
        buyer_addr,
        funding_tx_id: None,
        funding_outpoint: None,
        funding_amount: None,
        release_tx_id: None,
        refund_tx_id: None,
        dispute_tx_id: None,
    };

    state.escrows.lock().await.insert(id, entry);

    Ok((StatusCode::CREATED, Json(resp)))
}

// ─── GET /escrow/:id ─────────────────────────────────────────

async fn get_escrow(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusResponse> {
    // Snapshot entry data under lock, then drop before RPC calls.
    let snapshot = {
        let escrows = state.escrows.lock().await;
        let entry = escrows
            .get(&id)
            .ok_or_else(|| not_found("escrow not found"))?;
        (
            entry.id.clone(),
            compute_status(entry).to_string(),
            entry.buyer_addr.clone(),
            entry.config.escrow_amount,
            entry.config.pattern.clone(),
            entry.config.buyer_pk,
            entry.config.seller_pk,
            entry.funding_amount,
            entry.funding_tx_id.clone(),
            entry.release_tx_id.clone(),
            entry.refund_tx_id.clone(),
            entry.dispute_tx_id.clone(),
        )
    };
    let (
        eid,
        mut status,
        buyer_addr,
        escrow_amount,
        pattern,
        buyer_pk,
        seller_pk,
        mut utxo_amount,
        funding_tx_id,
        release_tx_id,
        refund_tx_id,
        dispute_tx_id,
    ) = snapshot;

    let mut current_daa = None;
    let mut rpc_error = None;

    // If awaiting_funding, check on-chain (lock already dropped)
    if status == "awaiting_funding" {
        match find_mature_utxo(&state.client, &buyer_addr).await {
            Ok(Some((_op, amount))) => {
                status = "funded".to_string();
                utxo_amount = Some(amount);
            }
            Ok(None) => {}
            Err(e) => rpc_error = Some(e),
        }
    }

    match state.client.get_block_dag_info().await {
        Ok(info) => current_daa = Some(info.virtual_daa_score),
        Err(e) => {
            if rpc_error.is_none() {
                rpc_error = Some(format!("RPC error: {e}"));
            }
        }
    }

    // If the only thing we tried was RPC and it failed, report it
    if status == "awaiting_funding" && rpc_error.is_some() {
        status = "awaiting_funding (node unreachable)".to_string();
    }

    Ok((
        StatusCode::OK,
        Json(StatusResponse {
            id: eid,
            status,
            funding_address: format!("{}", buyer_addr),
            escrow_amount,
            pattern: pattern_name(&pattern).to_string(),
            buyer_pk: hex::encode(buyer_pk),
            seller_pk: hex::encode(seller_pk),
            utxo_amount,
            current_daa,
            funding_tx_id,
            release_tx_id,
            refund_tx_id,
            dispute_tx_id,
        }),
    ))
}

// ─── POST /escrow/:id/fund ───────────────────────────────────

async fn fund_escrow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FundReq>,
) -> ApiResult<TxResponse> {
    // Phase 1: Lock, validate, clone what we need, drop lock before RPC.
    let (config, buyer_kp, buyer_addr, mode) = {
        let escrows = state.escrows.lock().await;
        let entry = escrows
            .get(&id)
            .ok_or_else(|| not_found("escrow not found"))?;

        if entry.funding_tx_id.is_some() {
            return Err(conflict("escrow already funded"));
        }
        (
            entry.config.clone(),
            entry.buyer_kp,
            entry.buyer_addr.clone(),
            entry.mode,
        )
    }; // lock dropped

    // Phase 2: Network I/O without holding the lock.
    let (outpoint, utxo_amount) = find_mature_utxo(&state.client, &buyer_addr)
        .await
        .map_err(internal)?
        .ok_or_else(|| conflict("no mature UTXO at buyer's address"))?;

    // Validate: UTXO must cover escrow_amount + fee exactly.
    // build_funding_tx sends (utxo_amount - fee) to P2SH with no change output,
    // so any excess above escrow_amount is locked and lost to miners on release.
    let escrow_amount = config.escrow_amount;
    let required = escrow_amount + req.fee;
    if utxo_amount < required {
        return Err(bad_request(format!(
            "UTXO amount {utxo_amount} too small: need at least {required} \
             (escrow {escrow_amount} + fee {})",
            req.fee
        )));
    }
    let overpayment = utxo_amount - required;
    if overpayment > escrow_amount / 10 {
        return Err(bad_request(format!(
            "UTXO amount {utxo_amount} too large: overpayment of {overpayment} sompi \
             would be lost (no change output). Send exactly {required} to the funding address"
        )));
    }

    // Build funding TX
    let funding_tx = build_funding_tx(outpoint, utxo_amount, &config, req.fee)
        .map_err(|e| bad_request(format!("{e}")))?;

    let buyer_spk = pay_to_address_script(&buyer_addr);
    let buyer_utxo = UtxoEntry::new(utxo_amount, buyer_spk, 0, false, None);

    // Sign
    let mut signed = funding_tx;
    if mode == SignerMode::Custodial {
        let kp = buyer_kp
            .as_ref()
            .ok_or_else(|| internal("no buyer keypair in custodial mode"))?;
        let sig = schnorr_sign(&signed, &buyer_utxo, kp);
        signed.inputs[0].signature_script = build_p2pk_sig_script(&sig);
    } else {
        let sig_hex = req
            .signature
            .as_ref()
            .ok_or_else(|| bad_request("signature required in external mode"))?;
        let sig = parse_hex_sig(sig_hex).map_err(bad_request)?;
        signed.inputs[0].signature_script = build_p2pk_sig_script(&sig);
    }

    // Verify locally
    verify_script(&signed, &buyer_utxo)
        .map_err(|e| bad_request(format!("verification failed: {e}")))?;

    // Submit
    let rpc_tx: RpcTransaction = (&signed).into();
    let tx_id = submit_with_retry(&state.client, rpc_tx)
        .await
        .map_err(internal)?;

    let funding_outpoint = TransactionOutpoint::new(signed.id(), 0);

    // Phase 3: Re-lock to update state, re-validate against races.
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows
            .get_mut(&id)
            .ok_or_else(|| internal("escrow disappeared"))?;
        if entry.funding_tx_id.is_some() {
            // Another request funded it while we were working — TX already submitted,
            // so this is harmless; just report the race.
            return Err(conflict("escrow was funded by a concurrent request"));
        }
        entry.funding_tx_id = Some(tx_id.clone());
        entry.funding_outpoint = Some(funding_outpoint);
        entry.funding_amount = Some(utxo_amount - req.fee);
    }

    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_id,
            status: "locked".to_string(),
            winner: None,
        }),
    ))
}

// ─── POST /escrow/:id/release ────────────────────────────────

async fn release_escrow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ReleaseReq>,
) -> ApiResult<TxResponse> {
    // Phase 1: Lock, validate, clone, build TX, sign — then drop lock.
    let signed_tx = {
        let escrows = state.escrows.lock().await;
        let entry = escrows
            .get(&id)
            .ok_or_else(|| not_found("escrow not found"))?;

        if entry.funding_tx_id.is_none() {
            return Err(conflict("escrow not funded yet"));
        }
        if entry.release_tx_id.is_some()
            || entry.refund_tx_id.is_some()
            || entry.dispute_tx_id.is_some()
        {
            return Err(conflict("escrow already settled"));
        }

        let escrow_outpoint = entry
            .funding_outpoint
            .ok_or_else(|| internal("missing funding outpoint"))?;
        let on_chain_value = entry
            .funding_amount
            .ok_or_else(|| internal("missing funding amount"))?;
        let escrow_utxo = UtxoEntry::new(
            on_chain_value,
            entry.config.p2sh_spk.clone(),
            0,
            false,
            None,
        );

        let is_payment_split = matches!(entry.config.pattern, EscrowPattern::PaymentSplit { .. });

        let mut tx = if is_payment_split {
            build_payment_split_tx(escrow_outpoint, &entry.config)
                .map_err(|e| bad_request(format!("{e}")))?
        } else {
            build_release_tx(escrow_outpoint, &entry.config, req.fee)
                .map_err(|e| bad_request(format!("{e}")))?
        };

        let (branch, sigs) = if is_payment_split {
            (Branch::CovenantRelease, vec![])
        } else if entry.mode == SignerMode::Custodial {
            let buyer_kp = entry
                .buyer_kp
                .as_ref()
                .ok_or_else(|| internal("no buyer keypair"))?;
            let seller_kp = entry
                .seller_kp
                .as_ref()
                .ok_or_else(|| internal("no seller keypair"))?;
            let b_sig = schnorr_sign(&tx, &escrow_utxo, buyer_kp);
            let s_sig = schnorr_sign(&tx, &escrow_utxo, seller_kp);
            (Branch::Normal, vec![b_sig, s_sig])
        } else {
            let ext_sigs = req
                .signatures
                .as_ref()
                .ok_or_else(|| bad_request("signatures required in external mode"))?;
            let sigs: Result<Vec<Vec<u8>>, _> = ext_sigs.iter().map(|s| parse_hex_sig(s)).collect();
            (Branch::Normal, sigs.map_err(bad_request)?)
        };

        let sig_script = build_sig_script(
            &branch,
            &sigs,
            &entry.config.redeem_script,
            &entry.config.pattern,
        )
        .map_err(|e| bad_request(format!("{e}")))?;

        tx.inputs[0].signature_script = sig_script;

        verify_script(&tx, &escrow_utxo)
            .map_err(|e| bad_request(format!("verification failed: {e}")))?;

        tx
    }; // lock dropped

    // Phase 2: Submit without holding the lock.
    let rpc_tx: RpcTransaction = (&signed_tx).into();
    let tx_id = submit_with_retry(&state.client, rpc_tx)
        .await
        .map_err(internal)?;

    // Phase 3: Re-lock to update state.
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows
            .get_mut(&id)
            .ok_or_else(|| internal("escrow disappeared"))?;
        if entry.release_tx_id.is_some() {
            return Err(conflict("escrow was released by a concurrent request"));
        }
        entry.release_tx_id = Some(tx_id.clone());
    }

    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_id,
            status: "released".to_string(),
            winner: None,
        }),
    ))
}

// ─── POST /escrow/:id/refund ─────────────────────────────────

async fn refund_escrow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RefundReq>,
) -> ApiResult<TxResponse> {
    // Phase 1: Lock, validate, build + sign TX, drop lock.
    let signed_refund = {
        let escrows = state.escrows.lock().await;
        let entry = escrows
            .get(&id)
            .ok_or_else(|| not_found("escrow not found"))?;

        if entry.funding_tx_id.is_none() {
            return Err(conflict("escrow not funded yet"));
        }
        if entry.release_tx_id.is_some()
            || entry.refund_tx_id.is_some()
            || entry.dispute_tx_id.is_some()
        {
            return Err(conflict("escrow already settled"));
        }

        let lock_time = match &entry.config.pattern {
            EscrowPattern::TimeLocked { lock_time } => *lock_time,
            EscrowPattern::CovenantMultiPath { lock_time } => *lock_time,
            _ => {
                return Err(bad_request(
                    "refund only available for timelocked and covenant_multi_path patterns",
                ));
            }
        };

        // Check DAA (quick RPC, acceptable under lock)
        let info = state
            .client
            .get_block_dag_info()
            .await
            .map_err(|e| internal(format!("RPC error: {e}")))?;
        let current_daa = info.virtual_daa_score;

        if current_daa < lock_time {
            return Err(conflict(format!(
                "timeout not yet available: current DAA {current_daa} < lock_time {lock_time}"
            )));
        }

        let escrow_outpoint = entry
            .funding_outpoint
            .ok_or_else(|| internal("missing funding outpoint"))?;
        let on_chain_value = entry
            .funding_amount
            .ok_or_else(|| internal("missing funding amount"))?;
        let escrow_utxo = UtxoEntry::new(
            on_chain_value,
            entry.config.p2sh_spk.clone(),
            0,
            false,
            None,
        );

        let refund_tx = build_refund_tx(escrow_outpoint, &entry.config, current_daa, req.fee)
            .map_err(|e| bad_request(format!("{e}")))?;

        let is_timelocked = matches!(entry.config.pattern, EscrowPattern::TimeLocked { .. });

        let sigs: Vec<Vec<u8>> = if is_timelocked {
            if entry.mode == SignerMode::Custodial {
                let buyer_kp = entry
                    .buyer_kp
                    .as_ref()
                    .ok_or_else(|| internal("no buyer keypair"))?;
                vec![schnorr_sign(&refund_tx, &escrow_utxo, buyer_kp)]
            } else {
                let sig_hex = req.signature.as_ref().ok_or_else(|| {
                    bad_request("signature required for timelocked refund in external mode")
                })?;
                vec![parse_hex_sig(sig_hex).map_err(bad_request)?]
            }
        } else {
            vec![] // CovenantMultiPath: no sigs
        };

        let sig_script = build_sig_script(
            &Branch::Timeout,
            &sigs,
            &entry.config.redeem_script,
            &entry.config.pattern,
        )
        .map_err(|e| bad_request(format!("{e}")))?;

        let mut tx = refund_tx;
        tx.inputs[0].signature_script = sig_script;

        verify_script(&tx, &escrow_utxo)
            .map_err(|e| bad_request(format!("verification failed: {e}")))?;

        tx
    }; // lock dropped

    // Phase 2: Submit without holding the lock.
    let rpc_tx: RpcTransaction = (&signed_refund).into();
    let tx_id = submit_with_retry(&state.client, rpc_tx)
        .await
        .map_err(internal)?;

    // Phase 3: Re-lock to update state.
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows
            .get_mut(&id)
            .ok_or_else(|| internal("escrow disappeared"))?;
        if entry.refund_tx_id.is_some() {
            return Err(conflict("escrow was refunded by a concurrent request"));
        }
        entry.refund_tx_id = Some(tx_id.clone());
    }

    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_id,
            status: "refunded".to_string(),
            winner: None,
        }),
    ))
}

// ─── POST /escrow/:id/dispute ────────────────────────────────

async fn dispute_escrow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DisputeReq>,
) -> ApiResult<TxResponse> {
    let winner = match req.winner.as_str() {
        "buyer" | "seller" => req.winner.clone(),
        _ => return Err(bad_request("winner must be 'buyer' or 'seller'")),
    };

    // Phase 1: Lock, validate, build + sign TX, drop lock.
    let signed_dispute = {
        let escrows = state.escrows.lock().await;
        let entry = escrows
            .get(&id)
            .ok_or_else(|| not_found("escrow not found"))?;

        if entry.funding_tx_id.is_none() {
            return Err(conflict("escrow not funded yet"));
        }
        if entry.release_tx_id.is_some()
            || entry.refund_tx_id.is_some()
            || entry.dispute_tx_id.is_some()
        {
            return Err(conflict("escrow already settled"));
        }

        let is_arbitrated = matches!(entry.config.pattern, EscrowPattern::Arbitrated);
        let is_covenant_mp = matches!(
            entry.config.pattern,
            EscrowPattern::CovenantMultiPath { .. }
        );
        if !is_arbitrated && !is_covenant_mp {
            return Err(bad_request(
                "dispute only available for arbitrated and covenant_multi_path patterns",
            ));
        }

        let escrow_outpoint = entry
            .funding_outpoint
            .ok_or_else(|| internal("missing funding outpoint"))?;
        let on_chain_value = entry
            .funding_amount
            .ok_or_else(|| internal("missing funding amount"))?;
        let escrow_utxo = UtxoEntry::new(
            on_chain_value,
            entry.config.p2sh_spk.clone(),
            0,
            false,
            None,
        );

        // Build dispute TX — pays to the winner (not hardcoded to seller)
        let winner_pk = if winner == "buyer" {
            entry.config.buyer_pk
        } else {
            entry.config.seller_pk
        };
        let winner_spk = p2pk_spk(&winner_pk);

        let dispute_tx = build_dispute_tx(escrow_outpoint, &entry.config, winner_spk, req.fee)
            .map_err(|e| bad_request(format!("{e}")))?;

        // Branch: Arbitrated uses Normal (plain 2-of-3), CovenantMultiPath uses Dispute
        // (OpFalse+OpTrue selectors for inner-else/outer-if).
        let branch = if is_covenant_mp {
            Branch::Dispute
        } else {
            Branch::Normal
        };

        let sigs = if entry.mode == SignerMode::Custodial {
            let arb_kp = entry
                .arbitrator_kp
                .as_ref()
                .ok_or_else(|| internal("no arbitrator keypair"))?;

            let winner_kp = if winner == "seller" {
                entry
                    .seller_kp
                    .as_ref()
                    .ok_or_else(|| internal("no seller keypair"))?
            } else {
                entry
                    .buyer_kp
                    .as_ref()
                    .ok_or_else(|| internal("no buyer keypair"))?
            };

            // Sigs must match pubkey order: buyer(0), seller(1), arbitrator(2)
            let mut sig_pairs: Vec<(usize, Vec<u8>)> = Vec::new();
            if winner == "seller" {
                sig_pairs.push((1, schnorr_sign(&dispute_tx, &escrow_utxo, winner_kp)));
                sig_pairs.push((2, schnorr_sign(&dispute_tx, &escrow_utxo, arb_kp)));
            } else {
                sig_pairs.push((0, schnorr_sign(&dispute_tx, &escrow_utxo, winner_kp)));
                sig_pairs.push((2, schnorr_sign(&dispute_tx, &escrow_utxo, arb_kp)));
            }
            sig_pairs.sort_by_key(|(pos, _)| *pos);
            sig_pairs.into_iter().map(|(_, s)| s).collect()
        } else {
            let ext_sigs = req
                .signatures
                .as_ref()
                .ok_or_else(|| bad_request("signatures required in external mode"))?;
            let sigs: Result<Vec<Vec<u8>>, _> = ext_sigs.iter().map(|s| parse_hex_sig(s)).collect();
            sigs.map_err(bad_request)?
        };

        let sig_script = build_sig_script(
            &branch,
            &sigs,
            &entry.config.redeem_script,
            &entry.config.pattern,
        )
        .map_err(|e| bad_request(format!("{e}")))?;

        let mut tx = dispute_tx;
        tx.inputs[0].signature_script = sig_script;

        verify_script(&tx, &escrow_utxo)
            .map_err(|e| bad_request(format!("verification failed: {e}")))?;

        tx
    }; // lock dropped

    // Phase 2: Submit without holding the lock.
    let rpc_tx: RpcTransaction = (&signed_dispute).into();
    let tx_id = submit_with_retry(&state.client, rpc_tx)
        .await
        .map_err(internal)?;

    // Phase 3: Re-lock to update state.
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows
            .get_mut(&id)
            .ok_or_else(|| internal("escrow disappeared"))?;
        if entry.dispute_tx_id.is_some() {
            return Err(conflict("escrow was disputed by a concurrent request"));
        }
        entry.dispute_tx_id = Some(tx_id.clone());
    }

    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_id,
            status: "disputed".to_string(),
            winner: Some(winner),
        }),
    ))
}

// ─── GET /escrow/:id/script ──────────────────────────────────

async fn get_script(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<ScriptResponse> {
    let escrows = state.escrows.lock().await;
    let entry = escrows
        .get(&id)
        .ok_or_else(|| not_found("escrow not found"))?;

    Ok((
        StatusCode::OK,
        Json(ScriptResponse {
            redeem_script_hex: hex::encode(&entry.config.redeem_script),
            disassembly: disassemble_script(&entry.config.redeem_script),
            length: entry.config.redeem_script.len(),
        }),
    ))
}

// ─── Router builder ──────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/escrow", post(create_escrow))
        .route("/escrow/{id}", get(get_escrow))
        .route("/escrow/{id}/fund", post(fund_escrow))
        .route("/escrow/{id}/release", post(release_escrow))
        .route("/escrow/{id}/refund", post(refund_escrow))
        .route("/escrow/{id}/dispute", post(dispute_escrow))
        .route("/escrow/{id}/script", get(get_script))
        .with_state(state)
}
