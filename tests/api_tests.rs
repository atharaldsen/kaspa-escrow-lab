//! Integration tests for the REST API.
//!
//! These tests run against the axum router directly (no live node needed).
//! An unconnected KaspaRpcClient is used — RPC calls will fail, but all
//! validation checks fire before RPC calls so we can test the full
//! validation layer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_escrow_lab::api::{
    AppState, EscrowEntry, SignerMode, SweepAction, build_router, classify_for_sweep,
};
use kaspa_escrow_lab::sdk::{EscrowBuilder, EscrowPattern};
use kaspa_escrow_lab::*;
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── Test helpers ───────────────────────────────────────────

/// Create an AppState with an unconnected RPC client (no node needed).
fn test_state() -> AppState {
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )
    .expect("client constructor should not fail");
    AppState {
        client: Arc::new(client),
        escrows: Arc::new(Mutex::new(HashMap::new())),
    }
}

/// Build a test router.
fn test_app() -> axum::Router {
    build_router(test_state())
}

/// Send a POST request with JSON body, return (status, parsed JSON).
async fn post_json(app: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

/// Send a GET request, return (status, parsed JSON).
async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

/// Create a basic escrow and return its id (for chaining tests).
async fn create_escrow(state: &AppState, body: &str) -> (StatusCode, Value) {
    let app = build_router(state.clone());
    post_json(app, "/escrow", body).await
}

/// Insert a pre-funded escrow directly into state (bypasses RPC).
async fn insert_funded_escrow(state: &AppState, pattern: EscrowPattern) -> String {
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();

    let mut builder = EscrowBuilder::new(pattern.clone())
        .buyer(buyer_pk)
        .seller(seller_pk)
        .amount(1_000_000_000);

    if matches!(
        pattern,
        EscrowPattern::Arbitrated | EscrowPattern::CovenantMultiPath { .. }
    ) {
        let (_kp, pk) = generate_keypair();
        builder = builder.arbitrator(pk);
    }
    if matches!(pattern, EscrowPattern::PaymentSplit { .. }) {
        let (_kp, pk) = generate_keypair();
        builder = builder.owner(pk);
        let (_kp2, pk2) = generate_keypair();
        builder = builder.fee_address(pk2);
    }

    let config = builder.build().expect("valid config");
    let id = uuid::Uuid::new_v4().to_string();
    let buyer_addr = testnet_address(&buyer_pk);

    let entry = EscrowEntry {
        id: id.clone(),
        config,
        mode: SignerMode::Custodial,
        buyer_kp: Some(buyer_kp),
        seller_kp: Some(seller_kp),
        arbitrator_kp: None,
        owner_kp: None,
        buyer_addr,
        funding_tx_id: Some("abcd1234".to_string()),
        funding_outpoint: Some(TransactionOutpoint::new(Default::default(), 0)),
        funding_amount: Some(1_000_000_000),
        release_tx_id: None,
        refund_tx_id: None,
        dispute_tx_id: None,
        escape_tx_id: None,
        expired: false,
        auto_refund_failures: 0,
    };

    state.escrows.lock().await.insert(id.clone(), entry);
    id
}

/// Insert a pre-funded escrow with a specific signer mode (for sweeper tests).
async fn insert_funded_escrow_with_mode(
    state: &AppState,
    pattern: EscrowPattern,
    mode: SignerMode,
) -> String {
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();

    let mut builder = EscrowBuilder::new(pattern.clone())
        .buyer(buyer_pk)
        .seller(seller_pk)
        .amount(1_000_000_000);

    if matches!(
        pattern,
        EscrowPattern::Arbitrated | EscrowPattern::CovenantMultiPath { .. }
    ) {
        let (_kp, pk) = generate_keypair();
        builder = builder.arbitrator(pk);
    }
    if matches!(pattern, EscrowPattern::PaymentSplit { .. }) {
        let (_kp, pk) = generate_keypair();
        builder = builder.owner(pk);
        let (_kp2, pk2) = generate_keypair();
        builder = builder.fee_address(pk2);
    }

    let config = builder.build().expect("valid config");
    let id = uuid::Uuid::new_v4().to_string();
    let buyer_addr = testnet_address(&buyer_pk);

    let entry = EscrowEntry {
        id: id.clone(),
        config,
        mode,
        buyer_kp: if mode == SignerMode::Custodial {
            Some(buyer_kp)
        } else {
            None
        },
        seller_kp: if mode == SignerMode::Custodial {
            Some(seller_kp)
        } else {
            None
        },
        arbitrator_kp: None,
        owner_kp: None,
        buyer_addr,
        funding_tx_id: Some("abcd1234".to_string()),
        funding_outpoint: Some(TransactionOutpoint::new(Default::default(), 0)),
        funding_amount: Some(1_000_000_000),
        release_tx_id: None,
        refund_tx_id: None,
        dispute_tx_id: None,
        escape_tx_id: None,
        expired: false,
        auto_refund_failures: 0,
    };

    state.escrows.lock().await.insert(id.clone(), entry);
    id
}

// ─── Create escrow tests ───────────────────────────────────

#[tokio::test]
async fn create_basic_custodial() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"basic","amount":1000000000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["mode"], "custodial");
    assert_eq!(json["status"], "awaiting_funding");
    assert_eq!(json["pattern"], "basic");
    assert_eq!(json["escrow_amount"], 1_000_000_000);
    assert!(json["id"].is_string());
    assert!(
        json["funding_address"]
            .as_str()
            .unwrap()
            .starts_with("kaspatest:")
    );
    assert!(json["buyer_pk"].is_string());
    assert!(json["seller_pk"].is_string());
    assert!(json["redeem_script_hex"].is_string());
}

#[tokio::test]
async fn create_all_patterns() {
    let cases = vec![
        (r#"{"pattern":"basic","amount":1000000}"#, "basic"),
        (r#"{"pattern":"arbitrated","amount":1000000}"#, "arbitrated"),
        (
            r#"{"pattern":"timelocked","amount":1000000,"lock_time":99999}"#,
            "timelocked",
        ),
        (
            r#"{"pattern":"covenant_multi_path","amount":1000000,"lock_time":99999}"#,
            "covenant_multi_path",
        ),
        (
            r#"{"pattern":"payment_split","amount":1000000,"fee_percent":5}"#,
            "payment_split",
        ),
    ];

    for (body, expected_pattern) in cases {
        let (status, json) = post_json(test_app(), "/escrow", body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "pattern {expected_pattern} failed"
        );
        assert_eq!(json["pattern"], expected_pattern);
    }
}

#[tokio::test]
async fn create_unknown_pattern() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"bogus","amount":1000000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("unknown pattern"));
}

#[tokio::test]
async fn create_partial_pubkeys() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"basic","amount":1000000,"buyer_pk":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("provide both"));
}

#[tokio::test]
async fn create_timelocked_missing_lock_time() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"timelocked","amount":1000000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("lock_time required")
    );
}

#[tokio::test]
async fn create_payment_split_missing_fee_percent() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"payment_split","amount":1000000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("fee_percent required")
    );
}

// ─── Get / Script endpoint tests ────────────────────────────

#[tokio::test]
async fn get_nonexistent() {
    let (status, json) = get_json(test_app(), "/escrow/nonexistent-id").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn get_script_success() {
    let state = test_state();
    let (status, created) = create_escrow(&state, r#"{"pattern":"basic","amount":1000000}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = get_json(app, &format!("/escrow/{id}/script")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["redeem_script_hex"].is_string());
    assert!(json["disassembly"].is_string());
    assert!(json["length"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn get_escrow_status() {
    let state = test_state();
    let (_, created) = create_escrow(&state, r#"{"pattern":"basic","amount":1000000}"#).await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = get_json(app, &format!("/escrow/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    // Status will be "awaiting_funding" or "awaiting_funding (node unreachable)"
    // since the RPC client is unconnected.
    assert!(
        json["status"]
            .as_str()
            .unwrap()
            .starts_with("awaiting_funding")
    );
    assert_eq!(json["pattern"], "basic");
}

// ─── State machine error tests ──────────────────────────────

#[tokio::test]
async fn release_not_found() {
    let (status, json) =
        post_json(test_app(), "/escrow/nonexistent/release", r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn release_not_funded() {
    let state = test_state();
    let (_, created) = create_escrow(&state, r#"{"pattern":"basic","amount":1000000}"#).await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/release"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("not funded"));
}

#[tokio::test]
async fn refund_wrong_pattern() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/refund"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("only available for timelocked")
    );
}

#[tokio::test]
async fn dispute_wrong_pattern() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(
        app,
        &format!("/escrow/{id}/dispute"),
        r#"{"winner":"seller","fee":5000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("only available for arbitrated")
    );
}

#[tokio::test]
async fn dispute_bad_winner() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Arbitrated).await;

    let app = build_router(state);
    let (status, json) = post_json(
        app,
        &format!("/escrow/{id}/dispute"),
        r#"{"winner":"nobody","fee":5000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("buyer' or 'seller'")
    );
}

// ─── Double-action prevention ───────────────────────────────

#[tokio::test]
async fn double_release() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    // Manually set release_tx_id to simulate a completed release
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.release_tx_id = Some("already-released-tx".to_string());
    }

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/release"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("already settled"));
}

#[tokio::test]
async fn fund_not_found() {
    let (status, json) = post_json(test_app(), "/escrow/nonexistent/fund", r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn fund_already_funded() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/fund"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("already funded"));
}

// ─── Escape endpoint tests ──────────────────────────────────

#[tokio::test]
async fn escape_not_found() {
    let (status, json) =
        post_json(test_app(), "/escrow/nonexistent/escape", r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn escape_not_funded() {
    let state = test_state();
    let (_, created) = create_escrow(
        &state,
        r#"{"pattern":"payment_split","amount":1000000,"fee_percent":5}"#,
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/escape"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("not funded"));
}

#[tokio::test]
async fn escape_wrong_pattern() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/escape"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("only available for payment_split")
    );
}

#[tokio::test]
async fn escape_already_settled() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::PaymentSplit { fee_percent: 5 }).await;

    // Simulate an already-escaped escrow
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.escape_tx_id = Some("already-escaped-tx".to_string());
    }

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/escape"), r#"{"fee":5000}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("already settled"));
}

// ─── Compound endpoint tests ────────────────────────────────

#[tokio::test]
async fn compound_not_found() {
    let (status, json) = post_json(test_app(), "/escrow/nonexistent/compound", r#"{}"#).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn compound_already_funded() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/compound"), r#"{}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["error"].as_str().unwrap().contains("already funded"));
}

#[tokio::test]
async fn compound_external_mode() {
    let state = test_state();
    // Create escrow with external pubkeys (both buyer and seller)
    let dummy_pk = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
    let body = format!(
        r#"{{"pattern":"basic","amount":1000000,"buyer_pk":"{}","seller_pk":"{}"}}"#,
        dummy_pk, dummy_pk
    );
    let (status, created) = create_escrow(&state, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/compound"), r#"{}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("custodial mode"));
}

// ─── Input validation tests ─────────────────────────────────

#[tokio::test]
async fn create_zero_amount() {
    let (status, json) =
        post_json(test_app(), "/escrow", r#"{"pattern":"basic","amount":0}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("amount must be > 0")
    );
}

#[tokio::test]
async fn create_timelocked_zero_lock_time() {
    let (status, json) = post_json(
        test_app(),
        "/escrow",
        r#"{"pattern":"timelocked","amount":1000000,"lock_time":0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("lock_time must be > 0")
    );
}

#[tokio::test]
async fn fee_too_large() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(
        app,
        &format!("/escrow/{id}/release"),
        r#"{"fee":99999999999}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("exceeds maximum"));
}

#[tokio::test]
async fn fee_zero() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/release"), r#"{"fee":0}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("fee must be > 0"));
}

// ─── Expiration / sweeper tests ────────────────────────────

#[tokio::test]
async fn expired_status_shows_in_get() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 100 }).await;

    // Mark as expired manually (simulates sweeper action)
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.expired = true;
    }

    let app = build_router(state);
    let (status, json) = get_json(app, &format!("/escrow/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["status"].as_str().unwrap().starts_with("expired"),
        "expected expired status, got: {}",
        json["status"]
    );
}

#[tokio::test]
async fn expired_escrow_still_accepts_refund() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 100 }).await;

    // Mark as expired
    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.expired = true;
    }

    // POST refund should NOT be rejected as "already settled"
    // (it will fail at RPC since client is unconnected, but that's after validation)
    let app = build_router(state);
    let (status, json) = post_json(app, &format!("/escrow/{id}/refund"), r#"{"fee":5000}"#).await;
    // Should fail at RPC (500), not at "already settled" (409)
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "expired escrow should not be rejected as settled: {}",
        json["error"]
    );
}

#[tokio::test]
async fn expires_at_daa_present_for_timelocked() {
    let state = test_state();
    let (_, created) = create_escrow(
        &state,
        r#"{"pattern":"timelocked","amount":1000000,"lock_time":99999}"#,
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (status, json) = get_json(app, &format!("/escrow/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["expires_at_daa"], 99999);
}

#[tokio::test]
async fn expires_at_daa_present_for_covenant() {
    let state = test_state();
    let (_, created) = create_escrow(
        &state,
        r#"{"pattern":"covenant_multi_path","amount":1000000,"lock_time":55555}"#,
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (_, json) = get_json(app, &format!("/escrow/{id}")).await;
    assert_eq!(json["expires_at_daa"], 55555);
}

#[tokio::test]
async fn expires_at_daa_absent_for_basic() {
    let state = test_state();
    let (_, created) = create_escrow(&state, r#"{"pattern":"basic","amount":1000000}"#).await;
    let id = created["id"].as_str().unwrap();

    let app = build_router(state);
    let (_, json) = get_json(app, &format!("/escrow/{id}")).await;
    assert!(json["expires_at_daa"].is_null());
}

// ─── classify_for_sweep tests ──────────────────────────────

#[tokio::test]
async fn classify_timelocked_custodial_auto_refund() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 100 }).await;

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();

    // Not expired yet
    assert!(classify_for_sweep(entry, 50).is_none());

    // Expired: should be AutoRefund
    let candidate = classify_for_sweep(entry, 200).expect("should be candidate");
    assert!(matches!(candidate.action, SweepAction::AutoRefund));
    assert_eq!(candidate.lock_time, 100);
}

#[tokio::test]
async fn classify_timelocked_external_mark_expired() {
    let state = test_state();
    let id = insert_funded_escrow_with_mode(
        &state,
        EscrowPattern::TimeLocked { lock_time: 100 },
        SignerMode::External,
    )
    .await;

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();

    let candidate = classify_for_sweep(entry, 200).expect("should be candidate");
    assert!(matches!(candidate.action, SweepAction::MarkExpired));
}

#[tokio::test]
async fn classify_covenant_any_mode_auto_refund() {
    let state = test_state();
    let id = insert_funded_escrow_with_mode(
        &state,
        EscrowPattern::CovenantMultiPath { lock_time: 100 },
        SignerMode::External,
    )
    .await;

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();

    let candidate = classify_for_sweep(entry, 200).expect("should be candidate");
    assert!(matches!(candidate.action, SweepAction::AutoRefund));
}

#[tokio::test]
async fn classify_not_expired_yet() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 1000 }).await;

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();

    assert!(classify_for_sweep(entry, 999).is_none());
}

#[tokio::test]
async fn classify_basic_not_eligible() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::Basic).await;

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();

    assert!(classify_for_sweep(entry, 999999).is_none());
}

#[tokio::test]
async fn classify_already_settled_skipped() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 100 }).await;

    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.refund_tx_id = Some("already-refunded".to_string());
    }

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();
    assert!(classify_for_sweep(entry, 200).is_none());
}

#[tokio::test]
async fn classify_already_expired_skipped() {
    let state = test_state();
    let id = insert_funded_escrow(&state, EscrowPattern::TimeLocked { lock_time: 100 }).await;

    {
        let mut escrows = state.escrows.lock().await;
        let entry = escrows.get_mut(&id).unwrap();
        entry.expired = true;
    }

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(&id).unwrap();
    assert!(classify_for_sweep(entry, 200).is_none());
}

#[tokio::test]
async fn classify_unfunded_skipped() {
    let state = test_state();
    let (_, created) = create_escrow(
        &state,
        r#"{"pattern":"timelocked","amount":1000000,"lock_time":100}"#,
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let escrows = state.escrows.lock().await;
    let entry = escrows.get(id).unwrap();
    assert!(classify_for_sweep(entry, 200).is_none());
}
