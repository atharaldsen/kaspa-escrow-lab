//! SDK Demo — EscrowBuilder API
//!
//! Demonstrates building all 5 escrow patterns using the type-safe builder,
//! then constructing and verifying transactions for each branch locally.
//! No network connection required.

use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_escrow_lab::sdk::{
    Branch, EscrowBuilder, EscrowConfig, EscrowPattern,
    tx::{
        build_dispute_tx, build_escape_tx, build_funding_tx, build_payment_split_tx,
        build_refund_tx, build_release_tx, build_sig_script,
    },
};
use kaspa_escrow_lab::*;

fn mock_outpoint() -> TransactionOutpoint {
    TransactionOutpoint::new(
        TransactionId::from_bytes([
            0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd,
        ]),
        0,
    )
}

fn verify_escrow_tx(
    escrow: &EscrowConfig,
    tx: &mut kaspa_consensus_core::tx::Transaction,
    sig_script: Vec<u8>,
    label: &str,
    expect_pass: bool,
) {
    tx.inputs[0].signature_script = sig_script;
    let utxo = UtxoEntry::new(
        escrow.escrow_amount,
        escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let result = verify_script(tx, &utxo);
    match (&result, expect_pass) {
        (Ok(()), true) => println!("  [{}] PASS", label),
        (Err(e), false) => println!("  [{}] FAIL as expected: {}", label, e),
        (Ok(()), false) => panic!("  [{}] Expected FAIL but got PASS!", label),
        (Err(e), true) => panic!("  [{}] Expected PASS but got: {}", label, e),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("SDK Demo — EscrowBuilder API");

    // Generate all keypairs
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();
    let (arb_kp, arb_pk) = generate_keypair();
    let (owner_kp, owner_pk) = generate_keypair();
    let (_, fee_pk) = generate_keypair();
    let amount: u64 = 10_000_000_000; // 100 KAS
    let fee: u64 = 5000;

    // ============================================================
    // Pattern 1: Basic 2-of-2
    // ============================================================
    print_step(1, "Basic 2-of-2 Escrow");
    let basic = EscrowBuilder::new(EscrowPattern::Basic)
        .buyer(buyer_pk)
        .seller(seller_pk)
        .amount(amount)
        .build()?;
    println!("  Redeem script: {} bytes", basic.redeem_script.len());

    // Fund
    let funding_tx = build_funding_tx(mock_outpoint(), amount + fee, &basic, fee)?;
    println!(
        "  Funding tx: {} inputs, {} outputs",
        funding_tx.inputs.len(),
        funding_tx.outputs.len()
    );

    // Release (buyer + seller sign)
    let mut release_tx = build_release_tx(mock_outpoint(), &basic, fee)?;
    let utxo = UtxoEntry::new(basic.escrow_amount, basic.p2sh_spk.clone(), 0, false, None);
    let buyer_sig = schnorr_sign(&release_tx, &utxo, &buyer_kp);
    let seller_sig = schnorr_sign(&release_tx, &utxo, &seller_kp);
    let sig_script = build_sig_script(
        &Branch::Normal,
        &[buyer_sig.clone(), seller_sig.clone()],
        &basic.redeem_script,
        &basic.pattern,
    )?;
    verify_escrow_tx(
        &basic,
        &mut release_tx,
        sig_script,
        "Basic 2-of-2 release",
        true,
    );

    // Single signer should fail
    let sig_script = build_sig_script(
        &Branch::Normal,
        &[buyer_sig],
        &basic.redeem_script,
        &basic.pattern,
    )?;
    verify_escrow_tx(
        &basic,
        &mut release_tx,
        sig_script,
        "Basic single-signer",
        false,
    );

    // ============================================================
    // Pattern 2: Arbitrated 2-of-3
    // ============================================================
    print_step(2, "Arbitrated 2-of-3 Escrow");
    let arb_escrow = EscrowBuilder::new(EscrowPattern::Arbitrated)
        .buyer(buyer_pk)
        .seller(seller_pk)
        .arbitrator(arb_pk)
        .amount(amount)
        .build()?;
    println!("  Redeem script: {} bytes", arb_escrow.redeem_script.len());

    // Normal release: buyer + seller
    let mut release_tx = build_release_tx(mock_outpoint(), &arb_escrow, fee)?;
    let utxo = UtxoEntry::new(
        arb_escrow.escrow_amount,
        arb_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&release_tx, &utxo, &buyer_kp);
    let s_sig = schnorr_sign(&release_tx, &utxo, &seller_kp);
    let sig_script = build_sig_script(
        &Branch::Normal,
        &[b_sig, s_sig],
        &arb_escrow.redeem_script,
        &arb_escrow.pattern,
    )?;
    verify_escrow_tx(
        &arb_escrow,
        &mut release_tx,
        sig_script,
        "Arbitrated buyer+seller",
        true,
    );

    // Dispute: arbitrator + buyer
    let a_sig = schnorr_sign(&release_tx, &utxo, &arb_kp);
    let b_sig = schnorr_sign(&release_tx, &utxo, &buyer_kp);
    let sig_script = build_sig_script(
        &Branch::Normal,
        &[b_sig, a_sig],
        &arb_escrow.redeem_script,
        &arb_escrow.pattern,
    )?;
    verify_escrow_tx(
        &arb_escrow,
        &mut release_tx,
        sig_script,
        "Arbitrated buyer+arb",
        true,
    );

    // ============================================================
    // Pattern 3: Time-Locked
    // ============================================================
    print_step(3, "Time-Locked Escrow");
    let lock_time = 100_000u64;
    let tl_escrow = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time })
        .buyer(buyer_pk)
        .seller(seller_pk)
        .amount(amount)
        .build()?;
    println!(
        "  Redeem script: {} bytes, lock_time: {}",
        tl_escrow.redeem_script.len(),
        lock_time
    );

    // Normal release (both sign, lock_time=0)
    let mut release_tx = build_release_tx(mock_outpoint(), &tl_escrow, fee)?;
    let utxo = UtxoEntry::new(
        tl_escrow.escrow_amount,
        tl_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&release_tx, &utxo, &buyer_kp);
    let s_sig = schnorr_sign(&release_tx, &utxo, &seller_kp);
    let sig_script = build_sig_script(
        &Branch::Normal,
        &[b_sig, s_sig],
        &tl_escrow.redeem_script,
        &tl_escrow.pattern,
    )?;
    verify_escrow_tx(
        &tl_escrow,
        &mut release_tx,
        sig_script,
        "TimeLocked normal release",
        true,
    );

    // Timeout refund (buyer-only, after lock_time)
    let mut refund_tx = build_refund_tx(mock_outpoint(), &tl_escrow, lock_time + 1, fee)?;
    let utxo = UtxoEntry::new(
        tl_escrow.escrow_amount,
        tl_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&refund_tx, &utxo, &buyer_kp);
    let sig_script = build_sig_script(
        &Branch::Timeout,
        &[b_sig],
        &tl_escrow.redeem_script,
        &tl_escrow.pattern,
    )?;
    verify_escrow_tx(
        &tl_escrow,
        &mut refund_tx,
        sig_script,
        "TimeLocked timeout refund",
        true,
    );

    // Timeout too early should fail
    let mut early_tx = build_refund_tx(mock_outpoint(), &tl_escrow, lock_time - 1, fee)?;
    let utxo = UtxoEntry::new(
        tl_escrow.escrow_amount,
        tl_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&early_tx, &utxo, &buyer_kp);
    let sig_script = build_sig_script(
        &Branch::Timeout,
        &[b_sig],
        &tl_escrow.redeem_script,
        &tl_escrow.pattern,
    )?;
    verify_escrow_tx(
        &tl_escrow,
        &mut early_tx,
        sig_script,
        "TimeLocked too early",
        false,
    );

    // ============================================================
    // Pattern 4: Covenant Multi-Path
    // ============================================================
    print_step(4, "Covenant Multi-Path Escrow");
    let cov_lock = 200_000u64;
    let cov_escrow = EscrowBuilder::new(EscrowPattern::CovenantMultiPath {
        lock_time: cov_lock,
    })
    .buyer(buyer_pk)
    .seller(seller_pk)
    .arbitrator(arb_pk)
    .amount(amount)
    .build()?;
    println!(
        "  Redeem script: {} bytes, lock_time: {}",
        cov_escrow.redeem_script.len(),
        cov_lock
    );

    // Branch 1: Normal 2-of-2
    let mut release_tx = build_release_tx(mock_outpoint(), &cov_escrow, fee)?;
    let utxo = UtxoEntry::new(
        cov_escrow.escrow_amount,
        cov_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&release_tx, &utxo, &buyer_kp);
    let s_sig = schnorr_sign(&release_tx, &utxo, &seller_kp);
    let sig_script = build_sig_script(
        &Branch::NormalInner,
        &[b_sig, s_sig],
        &cov_escrow.redeem_script,
        &cov_escrow.pattern,
    )?;
    verify_escrow_tx(
        &cov_escrow,
        &mut release_tx,
        sig_script,
        "Covenant branch1 (2-of-2)",
        true,
    );

    // Branch 2: Dispute 2-of-3 (buyer + arb)
    let mut dispute_tx = build_dispute_tx(mock_outpoint(), &cov_escrow, p2pk_spk(&buyer_pk), fee)?;
    let utxo = UtxoEntry::new(
        cov_escrow.escrow_amount,
        cov_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let b_sig = schnorr_sign(&dispute_tx, &utxo, &buyer_kp);
    let a_sig = schnorr_sign(&dispute_tx, &utxo, &arb_kp);
    let sig_script = build_sig_script(
        &Branch::Dispute,
        &[b_sig, a_sig],
        &cov_escrow.redeem_script,
        &cov_escrow.pattern,
    )?;
    verify_escrow_tx(
        &cov_escrow,
        &mut dispute_tx,
        sig_script,
        "Covenant branch2 (dispute)",
        true,
    );

    // Branch 3: Timeout with covenant constraints
    let mut refund_tx = build_refund_tx(mock_outpoint(), &cov_escrow, cov_lock + 1, fee)?;
    let sig_script = build_sig_script(
        &Branch::Timeout,
        &[],
        &cov_escrow.redeem_script,
        &cov_escrow.pattern,
    )?;
    verify_escrow_tx(
        &cov_escrow,
        &mut refund_tx,
        sig_script,
        "Covenant branch3 (timeout)",
        true,
    );

    // ============================================================
    // Pattern 5: Payment Split (Covenant)
    // ============================================================
    print_step(5, "Payment Split Escrow (Covenant)");
    let split_escrow = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
        .buyer(buyer_pk)
        .seller(seller_pk)
        .owner(owner_pk)
        .fee_address(fee_pk)
        .amount(amount)
        .build()?;
    println!(
        "  Redeem script: {} bytes",
        split_escrow.redeem_script.len()
    );
    println!(
        "  Seller gets: {} sompi ({}%)",
        split_escrow.seller_amount, 90
    );
    println!("  Fee gets:    {} sompi ({}%)", split_escrow.fee_amount, 10);

    // Covenant release (no signatures!)
    let mut split_tx = build_payment_split_tx(mock_outpoint(), &split_escrow)?;
    let sig_script = build_sig_script(
        &Branch::CovenantRelease,
        &[],
        &split_escrow.redeem_script,
        &split_escrow.pattern,
    )?;
    verify_escrow_tx(
        &split_escrow,
        &mut split_tx,
        sig_script,
        "PaymentSplit covenant release",
        true,
    );

    // Owner escape
    let mut escape_tx = build_escape_tx(mock_outpoint(), &split_escrow, p2pk_spk(&owner_pk), fee)?;
    let utxo = UtxoEntry::new(
        split_escrow.escrow_amount,
        split_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );
    let owner_sig = schnorr_sign(&escape_tx, &utxo, &owner_kp);
    let sig_script = build_sig_script(
        &Branch::OwnerEscape,
        &[owner_sig],
        &split_escrow.redeem_script,
        &split_escrow.pattern,
    )?;
    verify_escrow_tx(
        &split_escrow,
        &mut escape_tx,
        sig_script,
        "PaymentSplit owner escape",
        true,
    );

    // ============================================================
    // Summary
    // ============================================================
    println!("\n{}", "=".repeat(60));
    println!("  SDK Demo Complete — All 5 patterns verified locally!");
    println!("  Patterns tested:");
    println!("    1. Basic 2-of-2 multisig");
    println!("    2. Arbitrated 2-of-3 multisig");
    println!("    3. Time-locked with CLTV refund");
    println!("    4. Covenant multi-path (3 branches)");
    println!("    5. Payment split covenant (no-sig release)");
    println!("{}\n", "=".repeat(60));

    Ok(())
}
