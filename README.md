# kaspa-escrow-lab

Experimental escrow and covenant patterns on Kaspa Testnet 12.

TN12 is the first Kaspa network with full covenant support (KIP-17). This project explores what's possible with programmable UTXOs — multi-sig, timelocks, conditional branches, and introspection opcodes that enforce output constraints.

## Patterns

**Basic 2-of-2 escrow** — Buyer and seller must both sign to release funds. Simple but requires cooperation.

**2-of-3 with arbitrator** — Any two of buyer, seller, or arbitrator can sign. Handles disputes without requiring both original parties.

**Time-locked escrow** — Two spending paths: both sign for normal release, or buyer reclaims after a CLTV timeout. Uses `OpIf`/`OpElse` branching.

**Covenant escrow** — Three nested branches (normal / dispute / timeout) where the timeout path uses `OpTxOutputSpk` and `OpTxOutputAmount` to enforce that funds go to a specific address with a minimum amount. No signatures needed for the timeout path.

**Amount-constrained escrow** — Covenant enforces a payment split: output 0 must go to the seller with >= X sompi, output 1 must go to a fee address with >= Y sompi. Owner escape hatch via `OpCheckSig`.

## Running

```bash
# Local script verification (no node needed)
cargo run --example basic_escrow
cargo run --example multisig_escrow
cargo run --example timelock_escrow
cargo run --example covenant_escrow
cargo run --example amount_constrained_escrow

# Tests
cargo test

# Live on TN12 (requires running node + funded wallet)
cargo run --example connect_test
cargo run --example live_escrow
cargo run --example live_covenant_escrow
```

## TN12 node setup

```bash
# Terminal 1: node
kaspad --testnet --netsuffix=12 \
    --rpclisten-borsh=127.0.0.1:17110 \
    --utxoindex \
    --enable-unsynced-mining

# Terminal 2: wallet
kaspa-wallet
> connect ws://127.0.0.1:17110
> wallet create
> account create
> address

# Terminal 3: miner
kaspa-miner --mining-address <your_testnet_address>
```

The wallet and miner can be installed from source:

```bash
cargo install --git https://github.com/kaspanet/rusty-kaspa --branch tn12 kaspa-wallet
cargo install --git https://github.com/aspectron/kaspa-cpu-miner --branch main kaspa-miner
```

## Dependencies

All Kaspa crates come from the `tn12` branch of [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) via git dependencies. They're not on crates.io yet.

## Project structure

```
src/lib.rs                              shared helpers (keypair gen, signing, verification, disassembly)
src/main.rs                             prints usage
tests/escrow_tests.rs                   23 integration tests across all 5 patterns
examples/basic_escrow.rs                2-of-2 multisig
examples/multisig_escrow.rs             2-of-3 with arbitrator
examples/timelock_escrow.rs             OpIf/OpElse + CLTV timeout
examples/covenant_escrow.rs             nested branches + introspection opcodes
examples/amount_constrained_escrow.rs   payment split covenant
examples/connect_test.rs                TN12 node connection test
examples/live_escrow.rs                 on-chain 2-of-2 escrow
examples/live_covenant_escrow.rs        on-chain covenant timeout refund
```

## License

MIT
