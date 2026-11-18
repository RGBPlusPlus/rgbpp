# RGB++

RGB++ scripts

## Build

``` bash
# Build production binaries
make build
```

## Run tests

``` bash
# Build tests binaries, do not use test binaries in production!!!
make build CARGO_ARGS="--features=rgbpp-core/mock-bitcoin-light-client"
# Run tests
make test
```

### Non-mock SPV integration tests

```bash
make build BUILD_DIR=build/non-mock CARGO_ARGS=--locked
cargo test --locked -p tests --features non-mock-spv-tests --test non_mock_spv
```

This separate suite runs both locks with real Merkle/MMR verification in CKB-VM.
Fixtures use isolated easy-target chains and trusted client snapshots, not public
Bitcoin transactions or SPV type-script state updates. The Checksum workflow runs
it against the exact production binaries that passed the reproducibility checks.

### Core tests

Run core tests without building the RISC-V contracts:

```bash
cargo test --locked -p rgbpp-core
cargo test --locked -p rgbpp-core --features bitcoin-encoder,molecule/std
```

Add `--release` to test optimized builds. The encoder's host tests need
`molecule/std` for its buffer types. These tests supplement the contract tests;
they do not validate real SPV proofs in CKB VM.

## Audits

[audits](./audits/)
