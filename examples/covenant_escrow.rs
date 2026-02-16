//! Multi-Path Covenant Escrow
//!
//! Combines multisig, timelock, and covenant introspection opcodes into
//! a full escrow with three spending paths:
//!
//! - Branch 1 (normal): Buyer + Seller 2-of-2 multisig
//! - Branch 2 (dispute): 2-of-3 multisig (Buyer, Seller, Arbitrator)
//! - Branch 3 (timeout): After lock_time, buyer reclaims — covenant enforces
//!   that output goes to buyer's address with minimum amount

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::{
        OpCheckLockTimeVerify, OpCheckMultiSig, OpData65, OpElse, OpEndIf, OpEqualVerify, OpFalse,
        OpGreaterThanOrEqual, OpIf, OpTrue, OpTxOutputAmount, OpTxOutputSpk,
    },
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Multi-Path Covenant Escrow");

    // Step 1: Generate keypairs
    print_step(1, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();
    let (arbitrator_kp, arbitrator_pk) = generate_keypair();
    println!("  Buyer:      {}", hex::encode(buyer_pk));
    println!("  Seller:     {}", hex::encode(seller_pk));
    println!("  Arbitrator: {}", hex::encode(arbitrator_pk));

    let lock_time_value: u64 = 1000;
    let input_value: u64 = 1_000_000_000;
    let output_value: u64 = 999_900_000;

    // Buyer's P2PK SPK bytes (for covenant comparison)
    let buyer_spk = p2pk_spk(&buyer_pk);
    let buyer_spk_bytes = spk_to_bytes(&buyer_spk);

    // Step 2: Build the covenant escrow script
    //   OpIf                                              // outer branch selector
    //     OpIf                                            // inner branch selector
    //       2 <buyer_pk> <seller_pk> 2 OpCheckMultiSig   // Branch 1: normal release
    //     OpElse
    //       2 <buyer_pk> <seller_pk> <arb_pk> 3 OpCheckMultiSig  // Branch 2: dispute
    //     OpEndIf
    //   OpElse                                            // Branch 3: timeout refund
    //     <lock_time> OpCheckLockTimeVerify
    //     <buyer_spk_bytes> 0 OpTxOutputSpk OpEqualVerify  // covenant: output -> buyer
    //     0 OpTxOutputAmount <min_amount> OpGreaterThanOrEqual  // covenant: minimum amount
    //   OpEndIf
    print_step(2, "Building covenant escrow script...");
    let mut builder = ScriptBuilder::new();
    let redeem_script = builder
        // Outer if: signature paths vs timeout
        .add_op(OpIf)?
        // Inner if: normal vs dispute
        .add_op(OpIf)?
        // Branch 1: Normal release (buyer + seller)
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        // Branch 2: Dispute (any 2 of 3)
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_data(&arbitrator_pk)?
        .add_i64(3)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpEndIf)?
        .add_op(OpElse)?
        // Branch 3: Timeout refund with covenant constraints
        .add_i64(lock_time_value as i64)?
        .add_op(OpCheckLockTimeVerify)?
        // Covenant: output 0 must go to buyer's address
        .add_data(&buyer_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        // Covenant: output 0 amount must be >= minimum
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_i64(output_value as i64)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain();

    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());
    println!("  Lock time:     {} (DAA score)", lock_time_value);
    println!("  Min refund:    {} sompi", output_value);

    // Step 3: Branch 1 — Normal release (buyer + seller)
    print_step(3, "Branch 1: Normal release (buyer + seller)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&seller_pk),
                covenant: None,
            }],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);

        // sig_script: <buyer_sig> <seller_sig> OpTrue OpTrue <redeem_script>
        let mut sig_script: Vec<u8> = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&buyer_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&seller_sig);
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpTrue)?; // inner: select Branch 1
        sb.add_op(OpTrue)?; // outer: select signature paths
        sb.add_data(&redeem_script)?;
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Buyer + Seller", &result);
        assert!(result.is_ok());
    }

    // Step 4: Branch 2 — Dispute (arbitrator + buyer)
    print_step(4, "Branch 2: Dispute (arbitrator + buyer)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&buyer_pk),
                covenant: None,
            }],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let arbitrator_sig = schnorr_sign(&tx, &utxo, &arbitrator_kp);

        // sig_script: <buyer_sig> <arb_sig> OpFalse OpTrue <redeem_script>
        let mut sig_script: Vec<u8> = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&buyer_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&arbitrator_sig);
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?; // inner: select Branch 2
        sb.add_op(OpTrue)?; // outer: select signature paths
        sb.add_data(&redeem_script)?;
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Arbitrator + Buyer", &result);
        assert!(result.is_ok());
    }

    // Step 5: Branch 3 — Timeout refund (correct output)
    print_step(5, "Branch 3: Timeout refund (correct output)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: buyer_spk.clone(),
                covenant: None,
            }],
            lock_time_value + 100,
        );

        // sig_script: OpFalse <redeem_script> (no signatures needed)
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?; // outer: select timeout branch
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Timeout refund (correct)", &result);
        assert!(result.is_ok());
    }

    // Step 6: Branch 3 — Wrong destination address
    print_step(6, "Branch 3: Timeout refund to wrong address...");
    {
        let (_, wrong_pk) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&wrong_pk),
                covenant: None,
            }],
            lock_time_value + 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Wrong address", &result);
        assert!(result.is_err());
    }

    // Step 7: Branch 3 — Output amount too low
    print_step(7, "Branch 3: Timeout refund with insufficient amount...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value - 1, // 1 sompi short
                script_public_key: buyer_spk.clone(),
                covenant: None,
            }],
            lock_time_value + 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Amount too low", &result);
        assert!(result.is_err());
    }

    // Step 8: Branch 3 — Before timeout
    print_step(8, "Branch 3: Timeout refund before lock_time...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: buyer_spk.clone(),
                covenant: None,
            }],
            lock_time_value - 100, // too early
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Before timeout", &result);
        assert!(result.is_err());
    }

    println!("\n=== All covenant escrow tests passed ===\n");
    Ok(())
}
