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

## Audits

[audits](./audits/)


### Host-side core tests

These tests do not need RISC-V binaries, Docker, a node, wallet, or network data:

```bash
cargo test --locked -p rgbpp-core
cargo test --locked -p rgbpp-core --features bitcoin-encoder,molecule/std
```

The host encoder uses `molecule/std` for `BytesMut` and `BufMut`, just as the
existing VM test crate obtains it through dependency feature unification. This
explicit feature is for host-side tests, not production contract builds.

The `Core API tests` workflow runs both feature configurations independently of
contract VM tests. It covers script identity helpers, fixed-format seal outputs,
Molecule schema serialization, and a hand-assembled legacy Bitcoin transaction
with independently fixed byte and transaction-ID expectations. The encoder is
checked against those fixed bytes, rather than only against its own parser.

These are unit and **host-side API integration** tests, not contract integration
or SPV validation. The existing `Rust` workflow builds mock-light-client contracts
and runs the CKB-VM suite. A successful mock suite does **not** demonstrate that
real Bitcoin proofs are verified correctly. Real-SPV integration coverage and
reproducible deployment-artifact verification remain separate requirements.
