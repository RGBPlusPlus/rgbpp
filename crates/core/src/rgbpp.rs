use ckb_gen_types::{core::ScriptHashType, packed::Script, prelude::Unpack};

use crate::{
    bitcoin::BTCTx,
    schemas::rgbpp::{BTCTimeLock, RGBPPConfig, RGBPPLock},
};

pub fn check_utxo_seal(lock_args: &RGBPPLock, btc_tx: &BTCTx) -> bool {
    let out_index: u32 = lock_args.out_index().unpack();
    lock_args.btc_txid() == btc_tx.txid && out_index < btc_tx.outputs.len() as u32
}

pub fn check_btc_time_lock(lock_args: &BTCTimeLock, btc_tx: &BTCTx, min_lock: u32) -> bool {
    let after: u32 = lock_args.after().unpack();
    lock_args.btc_txid() == btc_tx.txid && after >= min_lock
}

pub fn is_btc_time_lock(config: &RGBPPConfig, lock: &Script) -> bool {
    lock.code_hash() == config.btc_time_lock_type_hash()
        && lock.hash_type() == ScriptHashType::Type.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{TxOut, MIN_BTC_TIME_LOCK_AFTER};
    use alloc::vec;
    use ckb_gen_types::prelude::*;

    #[test]
    fn seal_requires_matching_txid_and_an_existing_output() {
        let mut tx = BTCTx {
            txid: [1; 32].pack(),
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 1,
                script: vec![0x51].into(),
            }],
        };
        let lock = RGBPPLock::new_builder()
            .btc_txid(tx.txid.clone())
            .out_index(0u32.pack())
            .build();
        assert!(check_utxo_seal(&lock, &tx));
        for index in [1u32, u32::MAX] {
            assert!(!check_utxo_seal(
                &lock.clone().as_builder().out_index(index.pack()).build(),
                &tx
            ));
        }
        assert!(!check_utxo_seal(
            &lock.clone().as_builder().btc_txid([2; 32].pack()).build(),
            &tx
        ));
        tx.outputs.clear();
        assert!(!check_utxo_seal(&lock, &tx));
    }

    #[test]
    fn time_lock_requires_matching_txid_and_inclusive_minimum() {
        let tx = BTCTx {
            txid: [1; 32].pack(),
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        for (after, accepted) in [
            (0, false),
            (MIN_BTC_TIME_LOCK_AFTER - 1, false),
            (MIN_BTC_TIME_LOCK_AFTER, true),
            (u32::MAX, true),
        ] {
            let lock = BTCTimeLock::new_builder()
                .btc_txid(tx.txid.clone())
                .after(after.pack())
                .build();
            assert_eq!(
                check_btc_time_lock(&lock, &tx, MIN_BTC_TIME_LOCK_AFTER),
                accepted
            );
            assert!(!check_btc_time_lock(
                &lock.as_builder().btc_txid([2; 32].pack()).build(),
                &tx,
                MIN_BTC_TIME_LOCK_AFTER
            ));
        }
    }

    #[test]
    fn time_lock_identity_requires_both_configured_hash_and_type_hash_mode() {
        let config = RGBPPConfig::new_builder()
            .btc_time_lock_type_hash([1; 32].pack())
            .build();
        let lock = Script::new_builder()
            .code_hash(config.btc_time_lock_type_hash())
            .hash_type(ScriptHashType::Type.into())
            .build();
        assert!(is_btc_time_lock(&config, &lock));
        assert!(!is_btc_time_lock(
            &config,
            &lock.clone().as_builder().code_hash([2; 32].pack()).build()
        ));
        for hash_type in [ScriptHashType::Data, ScriptHashType::Data1] {
            assert!(!is_btc_time_lock(
                &config,
                &lock
                    .clone()
                    .as_builder()
                    .hash_type(hash_type.into())
                    .build()
            ));
        }
    }
}
