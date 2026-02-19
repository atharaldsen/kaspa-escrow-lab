use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_txscript::{
    opcodes::codes::{OpFalse, OpTrue},
    script_builder::ScriptBuilder,
};

use super::error::EscrowError;
use super::escrow::{EscrowConfig, EscrowPattern};
use crate::{build_p2pk_sig_script, p2pk_spk};

/// Which branch of the escrow script to execute.
#[derive(Debug, Clone)]
pub enum Branch {
    /// Outer if — used for Basic (2-of-2) and Arbitrated (2-of-3).
    Normal,
    /// Outer if + inner if — Branch 1 of CovenantMultiPath (2-of-2 normal).
    NormalInner,
    /// Outer if + inner else — Branch 2 of CovenantMultiPath (2-of-3 dispute).
    Dispute,
    /// Outer else — timeout refund (TimeLocked or CovenantMultiPath).
    Timeout,
    /// Outer else — covenant release path (PaymentSplit).
    CovenantRelease,
    /// Outer if — owner escape (PaymentSplit).
    OwnerEscape,
}

/// Build a funding transaction: buyer's P2PK UTXO -> escrow P2SH.
pub fn build_funding_tx(
    outpoint: TransactionOutpoint,
    utxo_amount: u64,
    escrow: &EscrowConfig,
    fee: u64,
) -> Result<Transaction, EscrowError> {
    if utxo_amount <= fee {
        return Err(EscrowError::InsufficientFunds {
            needed: fee + 1,
            available: utxo_amount,
        });
    }
    let input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output = TransactionOutput {
        value: utxo_amount - fee,
        script_public_key: escrow.p2sh_spk.clone(),
        covenant: None,
    };
    Ok(Transaction::new(
        1,
        vec![input],
        vec![output],
        0,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build a release transaction: escrow P2SH -> seller.
/// For Basic and Arbitrated patterns (multisig release).
pub fn build_release_tx(
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
    fee: u64,
) -> Result<Transaction, EscrowError> {
    if escrow.escrow_amount <= fee {
        return Err(EscrowError::InsufficientFunds {
            needed: fee + 1,
            available: escrow.escrow_amount,
        });
    }
    let input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let output = TransactionOutput {
        value: escrow.escrow_amount - fee,
        script_public_key: p2pk_spk(&escrow.seller_pk),
        covenant: None,
    };
    Ok(Transaction::new(
        1,
        vec![input],
        vec![output],
        0,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build a dispute release transaction: escrow -> winner's address.
pub fn build_dispute_tx(
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
    winner_spk: ScriptPublicKey,
    fee: u64,
) -> Result<Transaction, EscrowError> {
    if escrow.escrow_amount <= fee {
        return Err(EscrowError::InsufficientFunds {
            needed: fee + 1,
            available: escrow.escrow_amount,
        });
    }
    let input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let output = TransactionOutput {
        value: escrow.escrow_amount - fee,
        script_public_key: winner_spk,
        covenant: None,
    };
    Ok(Transaction::new(
        1,
        vec![input],
        vec![output],
        0,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build a timeout refund transaction (covenant branch 3).
/// For TimeLocked and CovenantMultiPath patterns.
pub fn build_refund_tx(
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
    current_daa: u64,
    fee: u64,
) -> Result<Transaction, EscrowError> {
    if escrow.escrow_amount <= fee {
        return Err(EscrowError::InsufficientFunds {
            needed: fee + 1,
            available: escrow.escrow_amount,
        });
    }
    let input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let output = TransactionOutput {
        value: escrow.escrow_amount - fee,
        script_public_key: p2pk_spk(&escrow.buyer_pk),
        covenant: None,
    };
    Ok(Transaction::new(
        1,
        vec![input],
        vec![output],
        current_daa,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build a covenant payment split release (no signatures needed).
/// For PaymentSplit pattern: output 0 -> seller, output 1 -> fee address.
pub fn build_payment_split_tx(
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
) -> Result<Transaction, EscrowError> {
    let input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let seller_pk = escrow.seller_pk;
    let fee_pk = escrow.fee_pk.ok_or_else(|| {
        EscrowError::InvalidConfig("fee pubkey required for payment split tx".into())
    })?;
    let outputs = vec![
        TransactionOutput {
            value: escrow.seller_amount,
            script_public_key: p2pk_spk(&seller_pk),
            covenant: None,
        },
        TransactionOutput {
            value: escrow.fee_amount,
            script_public_key: p2pk_spk(&fee_pk),
            covenant: None,
        },
    ];
    Ok(Transaction::new(
        1,
        vec![input],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build an owner escape transaction (PaymentSplit pattern).
/// Owner signs to spend escrow to any destination.
pub fn build_escape_tx(
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
    destination_spk: ScriptPublicKey,
    fee: u64,
) -> Result<Transaction, EscrowError> {
    if escrow.escrow_amount <= fee {
        return Err(EscrowError::InsufficientFunds {
            needed: fee + 1,
            available: escrow.escrow_amount,
        });
    }
    let input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let output = TransactionOutput {
        value: escrow.escrow_amount - fee,
        script_public_key: destination_spk,
        covenant: None,
    };
    Ok(Transaction::new(
        1,
        vec![input],
        vec![output],
        0,
        Default::default(),
        0,
        vec![],
    ))
}

/// Build the signature script for a given branch + signatures.
///
/// The sig_script format varies by branch:
/// - Normal: `<sigs...> <redeem_script>`
/// - NormalInner: `<sigs...> OpTrue OpTrue <redeem_script>`
/// - Dispute: `<sigs...> OpFalse OpTrue <redeem_script>`
/// - Timeout: `OpFalse <redeem_script>` (no signatures for covenant path)
///   or `<sig> OpFalse <redeem_script>` (for TimeLocked buyer-only)
/// - CovenantRelease: `OpFalse <redeem_script>` (no signatures)
/// - OwnerEscape: `<sig> OpTrue <redeem_script>`
pub fn build_sig_script(
    branch: &Branch,
    signatures: &[Vec<u8>],
    redeem_script: &[u8],
    pattern: &EscrowPattern,
) -> Result<Vec<u8>, EscrowError> {
    let mut sb = ScriptBuilder::new();

    match branch {
        Branch::Normal => {
            // Multisig sigs + optional OpTrue branch selector + redeem script.
            // TimeLocked uses OpIf/OpElse so needs OpTrue to select the if branch.
            // Basic/Arbitrated have no OpIf, so no selector needed.
            let mut script = Vec::new();
            for sig in signatures {
                script.extend_from_slice(&build_p2pk_sig_script(sig));
            }
            let needs_selector = matches!(pattern, EscrowPattern::TimeLocked { .. });
            let mut tail = ScriptBuilder::new();
            if needs_selector {
                tail.add_op(OpTrue)?;
            }
            tail.add_data(redeem_script)?;
            script.extend_from_slice(&tail.drain());
            return Ok(script);
        }

        Branch::NormalInner => {
            // CovenantMultiPath branch 1: sigs + OpTrue (inner if) + OpTrue (outer if)
            let mut script = Vec::new();
            for sig in signatures {
                script.extend_from_slice(&build_p2pk_sig_script(sig));
            }
            let tail = ScriptBuilder::new()
                .add_op(OpTrue)?
                .add_op(OpTrue)?
                .add_data(redeem_script)?
                .drain();
            script.extend_from_slice(&tail);
            return Ok(script);
        }

        Branch::Dispute => {
            // CovenantMultiPath branch 2: sigs + OpFalse (inner else) + OpTrue (outer if)
            let mut script = Vec::new();
            for sig in signatures {
                script.extend_from_slice(&build_p2pk_sig_script(sig));
            }
            let tail = ScriptBuilder::new()
                .add_op(OpFalse)?
                .add_op(OpTrue)?
                .add_data(redeem_script)?
                .drain();
            script.extend_from_slice(&tail);
            return Ok(script);
        }

        Branch::Timeout => {
            match pattern {
                EscrowPattern::TimeLocked { .. } => {
                    // TimeLocked timeout: buyer sig + OpFalse + redeem
                    if signatures.is_empty() {
                        return Err(EscrowError::InvalidConfig(
                            "TimeLocked timeout requires buyer signature".into(),
                        ));
                    }
                    let mut script = build_p2pk_sig_script(&signatures[0]);
                    let tail = ScriptBuilder::new()
                        .add_op(OpFalse)?
                        .add_data(redeem_script)?
                        .drain();
                    script.extend_from_slice(&tail);
                    return Ok(script);
                }
                _ => {
                    // CovenantMultiPath timeout: OpFalse + redeem (no signatures)
                    sb.add_op(OpFalse)?;
                    sb.add_data(redeem_script)?;
                }
            }
        }

        Branch::CovenantRelease => {
            // PaymentSplit covenant: OpFalse (select else branch) + redeem
            sb.add_op(OpFalse)?;
            sb.add_data(redeem_script)?;
        }

        Branch::OwnerEscape => {
            // PaymentSplit escape: sig + OpTrue + redeem
            if signatures.is_empty() {
                return Err(EscrowError::InvalidConfig(
                    "owner escape requires signature".into(),
                ));
            }
            sb.add_data(&signatures[0])?;
            sb.add_op(OpTrue)?;
            sb.add_data(redeem_script)?;
        }
    }

    Ok(sb.drain())
}
