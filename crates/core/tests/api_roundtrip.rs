//! Ordinary, host-side API integration tests. No VM or light-client proof is used.
use ckb_gen_types::{bytes::Bytes, core::ScriptHashType, packed::Script, prelude::*};
use rgbpp_core::{
    bitcoin::parse_btc_tx,
    schemas::rgbpp::{
        BTCTimeLock, BTCTimeLockConfig, BTCTimeUnlock, ExtraCommitmentData, RGBPPConfig, RGBPPLock,
        RGBPPUnlock,
    },
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

#[test]
fn fixed_config_and_lock_bytes_have_the_documented_layout() {
    // Fixed-size Molecule structs concatenate fields without table offsets.
    let config_bytes = [vec![0x34, 0x12], vec![0x22; 32], vec![0x33; 32]].concat();
    let config = RGBPPConfig::from_slice(&config_bytes).unwrap();
    let version: u16 = config.version().unpack();
    assert_eq!(version, 0x1234);
    assert_eq!(config.btc_lc_type_hash().as_slice(), &[0x22; 32]);
    assert_eq!(config.btc_time_lock_type_hash().as_slice(), &[0x33; 32]);
    assert_eq!(config.as_builder().build().as_slice(), config_bytes);

    let lock_bytes = [vec![0x78, 0x56, 0x34, 0x12], vec![0x44; 32]].concat();
    let lock = RGBPPLock::from_slice(&lock_bytes).unwrap();
    let index: u32 = lock.out_index().unpack();
    assert_eq!(index, 0x12345678);
    assert_eq!(lock.btc_txid().as_slice(), &[0x44; 32]);
    assert_eq!(lock.as_builder().build().as_slice(), lock_bytes);
}

#[test]
fn time_lock_config_has_only_the_light_client_hash() {
    let config = BTCTimeLockConfig::new_builder()
        .btc_lc_type_hash([0x77; 32].pack())
        .build();
    assert_eq!(config.as_slice(), &[0x77; 32]);
    let decoded = BTCTimeLockConfig::from_slice(config.as_slice()).unwrap();
    assert_eq!(decoded.btc_lc_type_hash().as_slice(), &[0x77; 32]);
}

#[test]
fn commitment_metadata_is_preserved_inside_unlock_witness() {
    let extra = ExtraCommitmentData::new_builder()
        .input_len(2u8.into())
        .output_len(3u8.into())
        .build();
    assert_eq!(extra.as_slice(), &[2, 3]);
    let witness = RGBPPUnlock::new_builder()
        .version(1u16.pack())
        .extra_data(extra.clone())
        .btc_tx(bytes(TX).pack())
        .btc_tx_proof(vec![4, 5, 6].pack())
        .build();
    let decoded = RGBPPUnlock::from_slice(witness.as_slice()).unwrap();
    let version: u16 = decoded.version().unpack();
    assert_eq!(version, 1);
    assert_eq!(decoded.extra_data().as_slice(), extra.as_slice());
    assert_eq!(decoded.btc_tx().raw_data(), bytes(TX));
    assert_eq!(decoded.btc_tx_proof().raw_data().as_ref(), &[4, 5, 6]);
}

#[test]
fn time_unlock_schema_keeps_opaque_bytes_separate_from_verification() {
    for payload in [vec![], vec![1, 2, 3, 4]] {
        // This test treats the field as opaque bytes; it does not parse a proof.
        let witness = BTCTimeUnlock::new_builder()
            .btc_tx_proof(payload.pack())
            .build();
        let decoded = BTCTimeUnlock::from_slice(witness.as_slice()).unwrap();
        assert_eq!(decoded.btc_tx_proof().raw_data().as_ref(), payload);
        assert_eq!(decoded.as_slice(), witness.as_slice());
    }
}

#[test]
fn sha256_helper_matches_known_vectors() {
    use rgbpp_core::bitcoin::sha2;
    assert_eq!(
        sha2(b"abc").as_slice(),
        bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_ref()
    );
    assert_eq!(
        sha2(b"").as_slice(),
        bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").as_ref()
    );
}

// A second independent fixture exercises collection ordering and script/data lengths.
const MULTI_TX: &str = "0100000002333333333333333333333333333333333333333333333333333333333333333302000000025152ffffffff44444444444444444444444444444444444444444444444444444444444444440500000003535455fdffffff0215cd5b07000000001976a914555555555555555555555555555555555555555588acb168de3a0000000016001466666666666666666666666666666666666666662a000000";
const MULTI_TXID: &str = "c2a5ace698765ae5fc949a5c4518b1813a7c310faf55202690f1ecb61b667203";

#[test]
fn parser_preserves_multiple_inputs_and_outputs_in_order() {
    let tx = parse_btc_tx(&bytes(MULTI_TX)).unwrap_or_else(|_| panic!("valid fixture"));
    assert_eq!(tx.txid.as_slice(), bytes(MULTI_TXID).as_ref());
    assert_eq!(tx.version, 1);
    assert_eq!(tx.lock_time, 42);
    assert_eq!(tx.inputs.len(), 2);
    for (input, (tag, index, script, sequence)) in tx.inputs.iter().zip([
        (0x33, 2, vec![0x51, 0x52], 0xffffffff),
        (0x44, 5, vec![0x53, 0x54, 0x55], 0xfffffffd),
    ]) {
        assert_eq!(input.previous_output.0.as_slice(), &[tag; 32]);
        assert_eq!(input.previous_output.1, index);
        assert_eq!(input.script.as_ref(), script);
        assert_eq!(input.sequence, sequence);
    }
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.outputs[0].value, 123456789);
    assert_eq!(
        tx.outputs[0].script,
        bytes("76a914555555555555555555555555555555555555555588ac")
    );
    assert_eq!(tx.outputs[1].value, 987654321);
    assert_eq!(
        tx.outputs[1].script,
        bytes("00146666666666666666666666666666666666666666")
    );
}

#[cfg(feature = "bitcoin-encoder")]
#[test]
fn encoder_preserves_multiple_inputs_outputs_and_ignores_cached_txid() {
    use rgbpp_core::bitcoin::{encode_btc_tx, BTCTx, TxIn, TxOut};
    for txid in [[0u8; 32], [0xa5; 32]] {
        let tx = BTCTx {
            txid: txid.pack(),
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: ([0x33; 32].pack(), 2),
                    script: vec![0x51, 0x52].into(),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: ([0x44; 32].pack(), 5),
                    script: vec![0x53, 0x54, 0x55].into(),
                    sequence: 0xfffffffd,
                },
            ],
            outputs: vec![
                TxOut {
                    value: 123456789,
                    script: bytes("76a914555555555555555555555555555555555555555588ac"),
                },
                TxOut {
                    value: 987654321,
                    script: bytes("00146666666666666666666666666666666666666666"),
                },
            ],
            lock_time: 42,
        };
        assert_eq!(encode_btc_tx(tx), bytes(MULTI_TX));
    }
}
