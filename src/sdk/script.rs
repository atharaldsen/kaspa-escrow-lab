use kaspa_txscript::{
    opcodes::codes::{
        OpCheckLockTimeVerify, OpCheckMultiSig, OpCheckSig, OpElse, OpEndIf, OpEqualVerify,
        OpGreaterThanOrEqual, OpIf, OpTxOutputAmount, OpTxOutputSpk, OpVerify,
    },
    script_builder::ScriptBuilder,
    standard::multisig_redeem_script,
};

use super::error::EscrowError;

/// Safely cast u64 to i64 for script data, returning an error if the value overflows.
fn safe_i64(value: u64, context: &str) -> Result<i64, EscrowError> {
    i64::try_from(value)
        .map_err(|_| EscrowError::ScriptBuild(format!("{context} value {value} exceeds i64::MAX")))
}

/// 2-of-2 multisig: buyer + seller must both sign.
pub fn build_basic_script(
    buyer_pk: &[u8; 32],
    seller_pk: &[u8; 32],
) -> Result<Vec<u8>, EscrowError> {
    multisig_redeem_script([*buyer_pk, *seller_pk].iter(), 2)
        .map_err(|e| EscrowError::ScriptBuild(format!("{e:?}")))
}

/// 2-of-3 arbitrated: any 2 of buyer/seller/arbitrator.
pub fn build_arbitrated_script(
    buyer_pk: &[u8; 32],
    seller_pk: &[u8; 32],
    arbitrator_pk: &[u8; 32],
) -> Result<Vec<u8>, EscrowError> {
    multisig_redeem_script([*buyer_pk, *seller_pk, *arbitrator_pk].iter(), 2)
        .map_err(|e| EscrowError::ScriptBuild(format!("{e:?}")))
}

/// Time-locked: 2-of-2 normal release OR buyer-only after CLTV timeout.
///
/// ```text
/// OpIf
///   2 <buyer> <seller> 2 OpCheckMultiSig
/// OpElse
///   <lock_time> OpCheckLockTimeVerify
///   <buyer_pk> OpCheckSig
/// OpEndIf
/// ```
pub fn build_timelocked_script(
    buyer_pk: &[u8; 32],
    seller_pk: &[u8; 32],
    lock_time: u64,
) -> Result<Vec<u8>, EscrowError> {
    Ok(ScriptBuilder::new()
        .add_op(OpIf)?
        .add_i64(2)?
        .add_data(buyer_pk)?
        .add_data(seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        .add_i64(safe_i64(lock_time, "lock_time")?)?
        .add_op(OpCheckLockTimeVerify)?
        .add_data(buyer_pk)?
        .add_op(OpCheckSig)?
        .add_op(OpEndIf)?
        .drain())
}

/// Covenant multi-path: 2-of-2 normal OR 2-of-3 dispute OR timeout with
/// covenant-enforced output constraints (address + minimum amount).
///
/// ```text
/// OpIf
///   OpIf
///     2 <buyer> <seller> 2 OpCheckMultiSig       // Branch 1: normal
///   OpElse
///     2 <buyer> <seller> <arb> 3 OpCheckMultiSig  // Branch 2: dispute
///   OpEndIf
/// OpElse
///   <lock_time> OpCheckLockTimeVerify              // Branch 3: timeout
///   <buyer_spk_bytes> 0 OpTxOutputSpk OpEqualVerify
///   0 OpTxOutputAmount <refund_amount> OpGreaterThanOrEqual
/// OpEndIf
/// ```
pub fn build_covenant_multipath_script(
    buyer_pk: &[u8; 32],
    seller_pk: &[u8; 32],
    arbitrator_pk: &[u8; 32],
    lock_time: u64,
    buyer_spk_bytes: &[u8],
    refund_amount: u64,
) -> Result<Vec<u8>, EscrowError> {
    Ok(ScriptBuilder::new()
        .add_op(OpIf)?
        .add_op(OpIf)?
        .add_i64(2)?
        .add_data(buyer_pk)?
        .add_data(seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        .add_i64(2)?
        .add_data(buyer_pk)?
        .add_data(seller_pk)?
        .add_data(arbitrator_pk)?
        .add_i64(3)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpEndIf)?
        .add_op(OpElse)?
        .add_i64(safe_i64(lock_time, "lock_time")?)?
        .add_op(OpCheckLockTimeVerify)?
        .add_data(buyer_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_i64(safe_i64(refund_amount, "refund_amount")?)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain())
}

/// Payment split: owner escape OR covenant-enforced multi-output payment routing.
///
/// ```text
/// OpIf
///   <owner_pk> OpCheckSig                              // Escape: owner overrides
/// OpElse
///   <seller_spk> 0 OpTxOutputSpk OpEqualVerify         // Output 0 -> seller
///   0 OpTxOutputAmount <seller_amount> OpGreaterThanOrEqual OpVerify
///   <fee_spk> 1 OpTxOutputSpk OpEqualVerify            // Output 1 -> fee
///   1 OpTxOutputAmount <fee_amount> OpGreaterThanOrEqual
/// OpEndIf
/// ```
pub fn build_payment_split_script(
    owner_pk: &[u8; 32],
    seller_spk_bytes: &[u8],
    seller_amount: u64,
    fee_spk_bytes: &[u8],
    fee_amount: u64,
) -> Result<Vec<u8>, EscrowError> {
    Ok(ScriptBuilder::new()
        .add_op(OpIf)?
        .add_data(owner_pk)?
        .add_op(OpCheckSig)?
        .add_op(OpElse)?
        .add_data(seller_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_i64(safe_i64(seller_amount, "seller_amount")?)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpVerify)?
        .add_data(fee_spk_bytes)?
        .add_i64(1)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        .add_i64(1)?
        .add_op(OpTxOutputAmount)?
        .add_i64(safe_i64(fee_amount, "fee_amount")?)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain())
}
