//! Time-Locked Escrow
//!
//! Two spending paths:
//! - Path A (normal): Buyer + Seller both sign (2-of-2 multisig)
//! - Path B (timeout): After lock_time expires, buyer can reclaim unilaterally
//!
//! Uses OpCheckLockTimeVerify to enforce the timeout. Note: Kaspa's CLTV
//! pops its argument from the stack (unlike Bitcoin's NOP-style CLTV).

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::{
        OpCheckLockTimeVerify, OpCheckMultiSig, OpCheckSig, OpData65, OpElse, OpEndIf, OpFalse,
        OpIf, OpTrue,
    },
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Time-Locked Escrow");

    // Step 1: Generate keypairs
    print_step(1, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();
    println!("  Buyer:  {}", hex::encode(buyer_pk));
    println!("  Seller: {}", hex::encode(seller_pk));

    // Lock time as DAA score (must be below LOCK_TIME_THRESHOLD = 500_000_000_000)
    let lock_time_value: u64 = 1000;
    println!("  Lock time (DAA score): {}", lock_time_value);

    // Step 2: Build time-locked escrow script
    //   OpIf
    //     2 <buyer_pk> <seller_pk> 2 OpCheckMultiSig    // Normal release
    //   OpElse
    //     <lock_time> OpCheckLockTimeVerify              // CLTV pops lock_time
    //     <buyer_pk> OpCheckSig                          // Buyer-only refund
    //   OpEndIf
    print_step(2, "Building time-locked escrow script...");
    let mut builder = ScriptBuilder::new();
    let redeem_script = builder
        .add_op(OpIf)?
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        .add_i64(lock_time_value as i64)?
        .add_op(OpCheckLockTimeVerify)? // pops and validates; no OpDrop needed
        .add_data(&buyer_pk)?
        .add_op(OpCheckSig)?
        .add_op(OpEndIf)?
        .drain();

    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());

    let input_value: u64 = 1_000_000_000;
    let output_value: u64 = 999_900_000;

    let make_output = |pk: &[u8; 32]| TransactionOutput {
        value: output_value,
        script_public_key: p2pk_spk(pk),
        covenant: None,
    };

    // Step 3: Path A — Normal release (buyer + seller sign, any lock_time)
    print_step(3, "Path A: Normal release (buyer + seller sign)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output(&seller_pk)],
            0, // lock_time irrelevant for this path
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);

        let mut sb = ScriptBuilder::new();
        let mut sig_script = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&buyer_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&seller_sig);
        sb.add_op(OpTrue)?; // select OpIf branch
        sb.add_data(&redeem_script)?;
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Both sign (normal)", &result);
        assert!(result.is_ok());
    }

    // Step 4: Path B — Timeout refund (buyer only, after lock_time)
    print_step(4, "Path B: Timeout refund (buyer only, lock_time met)...");
    {
        // tx.lock_time >= script lock_time, and sequence < u64::MAX
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output(&buyer_pk)],
            lock_time_value + 100, // tx lock_time > required
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);

        let mut sb = ScriptBuilder::new();
        sb.add_data(&buyer_sig)?;
        sb.add_op(OpFalse)?; // select OpElse branch
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Buyer refund (timeout met)", &result);
        assert!(result.is_ok());
    }

    // Step 5: Path B — Should fail if lock_time not yet reached
    print_step(5, "Path B: Buyer refund attempt before timeout...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output(&buyer_pk)],
            lock_time_value - 100, // tx lock_time < required
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);

        let mut sb = ScriptBuilder::new();
        sb.add_data(&buyer_sig)?;
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Too early", &result);
        assert!(result.is_err());
    }

    // Step 6: Path B — Wrong key after timeout
    print_step(6, "Path B: Wrong key after timeout...");
    {
        let (wrong_kp, _) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output(&buyer_pk)],
            lock_time_value + 100,
        );

        let wrong_sig = schnorr_sign(&tx, &utxo, &wrong_kp);

        let mut sb = ScriptBuilder::new();
        sb.add_data(&wrong_sig)?;
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Wrong key", &result);
        assert!(result.is_err());
    }

    println!("\n=== All timelock escrow tests passed ===\n");
    Ok(())
}
