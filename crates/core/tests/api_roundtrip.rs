//! Ordinary, host-side API integration tests. No VM or light-client proof is used.
use ckb_gen_types::{bytes::Bytes, core::ScriptHashType, packed::Script, prelude::*};
use rgbpp_core::{
    bitcoin::parse_btc_tx,
    schemas::rgbpp::{BTCTimeLock, RGBPPConfig, RGBPPLock, RGBPPUnlock},
};

// Hand-assembled legacy transaction: version 2, one input, two outputs, locktime 500.
// This is a serialization fixture, not an on-chain transaction or SPV proof.
const TX: &str = "02000000011111111111111111111111111111111111111111111111111111111111111111030000000151feffffff02e80300000000000001510000000000000000226a202222222222222222222222222222222222222222222222222222222222222222f4010000";
const TXID: &str = "174680dc37e6efd5e67c83ee51001ba26fb0f27b6456a1138a4d55ed3c412be1";

fn bytes(hex: &str) -> Bytes {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .into()
}

#[test]
fn parser_reads_a_fixed_transaction_fixture() {
    let tx = parse_btc_tx(&bytes(TX)).unwrap_or_else(|_| panic!("valid fixture"));
    assert_eq!(tx.txid.as_slice(), bytes(TXID).as_ref());
    assert_eq!(tx.version, 2);
    assert_eq!(tx.lock_time, 500);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.inputs[0].previous_output.0.as_slice(), &[0x11; 32]);
    assert_eq!(tx.inputs[0].previous_output.1, 3);
    assert_eq!(tx.inputs[0].script.as_ref(), &[0x51]);
    assert_eq!(tx.inputs[0].sequence, 0xfffffffe);
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.outputs[0].value, 1000);
    assert_eq!(tx.outputs[0].script.as_ref(), &[0x51]);
    assert_eq!(tx.outputs[1].value, 0);
    assert_eq!(&tx.outputs[1].script[..2], &[0x6a, 0x20]);
    assert_eq!(&tx.outputs[1].script[2..], &[0x22; 32]);
}

#[cfg(feature = "bitcoin-encoder")]
#[test]
fn encoder_matches_fixed_bytes_instead_of_only_roundtripping() {
    use rgbpp_core::bitcoin::{encode_btc_tx, BTCTx, TxIn, TxOut};
    let tx = BTCTx {
        txid: Default::default(), // Encoder must calculate bytes independently of this field.
        version: 2,
        inputs: vec![TxIn {
            previous_output: ([0x11; 32].pack(), 3),
            script: vec![0x51].into(),
            sequence: 0xfffffffe,
        }],
        outputs: vec![
            TxOut {
                value: 1000,
                script: vec![0x51].into(),
            },
            TxOut::new_seal(0, [0x22; 32]),
        ],
        lock_time: 500,
    };
    assert_eq!(encode_btc_tx(tx), bytes(TX));
}

#[test]
fn lock_and_config_schemas_preserve_fields() {
    let lock = RGBPPLock::new_builder()
        .out_index(3u32.pack())
        .btc_txid([0x11; 32].pack())
        .build();
    let decoded = RGBPPLock::from_slice(lock.as_slice()).unwrap();
    assert_eq!(decoded.as_slice(), lock.as_slice());
    assert_eq!(decoded.out_index().as_slice(), &3u32.to_le_bytes());
    assert_eq!(decoded.btc_txid().as_slice(), &[0x11; 32]);

    let config = RGBPPConfig::new_builder()
        .version(1u16.pack())
        .btc_lc_type_hash([0x22; 32].pack())
        .btc_time_lock_type_hash([0x33; 32].pack())
        .build();
    let decoded = RGBPPConfig::from_slice(config.as_slice()).unwrap();
    assert_eq!(decoded.as_slice(), config.as_slice());
    assert_eq!(decoded.version().as_slice(), &[1, 0]);
    assert_eq!(decoded.btc_lc_type_hash().as_slice(), &[0x22; 32]);
    assert_eq!(decoded.btc_time_lock_type_hash().as_slice(), &[0x33; 32]);
}

#[test]
fn time_lock_schema_preserves_nested_script() {
    let script = Script::new_builder()
        .code_hash([0x44; 32].pack())
        .hash_type(ScriptHashType::Type.into())
        .args(vec![1, 2, 3].pack())
        .build();
    let lock = BTCTimeLock::new_builder()
        .lock_script(script.clone())
        .after(6u32.pack())
        .btc_txid([0x55; 32].pack())
        .build();
    let decoded = BTCTimeLock::from_slice(lock.as_slice()).unwrap();
    assert_eq!(decoded.lock_script(), script);
    assert_eq!(decoded.after().as_slice(), &6u32.to_le_bytes());
    assert_eq!(decoded.btc_txid().as_slice(), &[0x55; 32]);
}

#[test]
fn unlock_schema_preserves_opaque_payload_bytes() {
    // Only exercises molecule serialization; these bytes are not a proof fixture.
    let witness = RGBPPUnlock::new_builder()
        .version(1u16.pack())
        .btc_tx(bytes(TX).pack())
        .btc_tx_proof(vec![1, 2, 3].pack())
        .build();
    let decoded = RGBPPUnlock::from_slice(witness.as_slice()).unwrap();
    assert_eq!(decoded.as_slice(), witness.as_slice());
    assert_eq!(decoded.btc_tx().raw_data(), bytes(TX));
    assert_eq!(decoded.btc_tx_proof().raw_data().as_ref(), &[1, 2, 3]);
}
