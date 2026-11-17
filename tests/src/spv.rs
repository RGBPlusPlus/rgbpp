//! Mainnet proofs run through the verifier the contracts link.
//!
//! CI builds the contracts with `mock-bitcoin-light-client`, which skips SPV verification, so the
//! contract tests in this crate can't notice a verifier problem. These tests can.

use ckb_bitcoin_spv_verifier::{
    error::VerifyTxError,
    types::{packed, prelude::*},
};
use serde_json::Value;

fn verify(name: &str) -> Result<(), i8> {
    let fixtures: Value =
        serde_json::from_str(include_str!("../fixtures/spv-proofs.json")).expect("fixtures");
    let bytes = |key: &str| {
        let value = fixtures[name][key].as_str().expect(key);
        hex_decode(value.trim_start_matches("0x"))
    };
    let client = packed::SpvClient::from_slice(&bytes("client")).expect("client");
    let proof = bytes("proof");
    let proof = packed::TransactionProofReader::from_slice(&proof).expect("proof");
    let txid: [u8; 32] = bytes("txid").try_into().expect("txid");
    let confirmations = fixtures[name]["confirmations"]
        .as_u64()
        .expect("confirmations") as u32;
    client
        .verify_transaction(&txid, proof, confirmations)
        .map(|_| ())
        .map_err(|err| err as i8)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn test_forged_header_is_rejected() {
    assert_eq!(verify("forged"), Err(VerifyTxError::HeaderMmrProof as i8));
}

#[test]
fn test_genuine_proofs_are_accepted() {
    assert_eq!(verify("genuine_rgbpp"), Ok(()));
    assert_eq!(verify("genuine_btc_time"), Ok(()));
}
