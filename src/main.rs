//! Kaspa Escrow Lab
//!
//! Experimental project for learning covenant and escrow patterns on Kaspa Testnet 12.
//!
//! ## Goals
//! - Understand covenant script construction (SilverScript/txscript)
//! - Experiment with programmable UTXOs (multi-sig, timelocks, conditional paths)
//! - Learn wallet interaction with escrow structures
//!
//! ## Running Examples
//! ```bash
//! cargo run --example basic_escrow
//! cargo run --example multisig_escrow
//! cargo run --example timelock_escrow
//! ```

fn main() {
    println!("Kaspa Escrow Lab");
    println!("================");
    println!();
    println!("Run examples to experiment with covenant patterns:");
    println!("  cargo run --example basic_escrow");
    println!("  cargo run --example multisig_escrow");
    println!("  cargo run --example timelock_escrow");
}
