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
