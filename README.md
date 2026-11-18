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
# Build the pinned SPV type script used by the composed update/consume tests.
git clone --no-checkout https://github.com/RGBPlusPlus/ckb-bitcoin-spv-contracts build/spv-contracts-src
git -C build/spv-contracts-src checkout 0ebc91158c241c514ad670971730515e4e4e39cc
git -C build/spv-contracts-src submodule update --init deps/ckb-c-stdlib
make -C build/spv-contracts-src build CONTRACT=ckb-bitcoin-spv-type-lock CARGO_ARGS=--locked
cp build/spv-contracts-src/build/release/ckb-bitcoin-spv-type-lock build/non-mock/
cargo test --locked -p tests --features non-mock-spv-tests --test non_mock_spv
```

This separate suite runs both locks with real Merkle/MMR verification in CKB-VM.
Fixtures use isolated easy-target chains and a trusted initial checkpoint, not
public Bitcoin transactions. In addition to snapshot-based cases, composed tests
validate the SPV type-script update in the VM and then consume its exact output
with both RGB++ locks. This does not validate initial checkpoint admission or the
operator ownership lock. The Checksum workflow tests the exact checksummed RGB++
binaries and records the pinned SPV dependency source and binary hash.

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
