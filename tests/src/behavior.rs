//! Contract regressions executed by CKB-VM with the mock-light-client binaries.
//! Bitcoin transactions are synthetic; check_btc_tx_exists is bypassed, so these
//! tests establish lock/commitment behavior, not SPV inclusion or confirmations.
use crate::rgbpp::{
    build_btc_time_lock_tx, build_rgbpp_tx, gen_commitment, set_cell_btc_txid, LockDesc, OutputDesc,
};
use crate::{utils::TestScripts, Loader};
use ckb_testtool::{
    ckb_types::{bytes::Bytes, core::TransactionView, packed::*, prelude::*},
    context::Context,
};
use rgbpp_core::{
    bitcoin::{encode_btc_tx, parse_btc_tx, sha2, TxOut},
    error::Error,
    schemas::rgbpp::{RGBPPLock, RGBPPUnlock},
};

const MAX_CYCLES: u64 = 10_000_000;

fn fixture(time_lock: bool) -> (Context, TestScripts, TransactionView) {
    let mut context = Context::default();
    let scripts = TestScripts::setup(&Loader::default(), &mut context);
    let desc = vec![OutputDesc {
        lock: if time_lock {
            LockDesc::UserLock(Default::default())
        } else {
            LockDesc::Rgbpp
        },
        amount: 1000,
    }];
    let tx = if time_lock {
        build_btc_time_lock_tx(&mut context, &scripts, 1000, desc)
    } else {
        build_rgbpp_tx(&mut context, &scripts, 1000, desc)
    };
    let tx = context.complete_tx(tx);
    passes(&context, &tx);
    (context, scripts, tx)
}

fn passes(context: &Context, tx: &TransactionView) {
    context
        .verify_tx(tx, MAX_CYCLES)
        .expect("control transaction passes");
}

fn fails(context: &Context, tx: &TransactionView, expected: Error) {
    fails_at(context, tx, expected, 0);
}

fn fails_at(context: &Context, tx: &TransactionView, expected: Error, index: usize) {
    use ckb_testtool::ckb_script::{ScriptError, TransactionScriptError};
    let input = tx.inputs().get(index).unwrap();
    let (cell, _) = context.get_cell(&input.previous_output()).unwrap();
    let expected =
        ScriptError::validation_failure(&cell.lock(), expected as i8).input_lock_script(index);
    let actual = context
        .verify_tx(tx, MAX_CYCLES)
        .expect_err("mutation rejected");
    assert_eq!(
        actual.root_cause().downcast_ref::<TransactionScriptError>(),
        Some(&expected)
    );
}

fn unlock(tx: &TransactionView) -> RGBPPUnlock {
    let witness = WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
    RGBPPUnlock::from_slice(&witness.lock().to_opt().unwrap().raw_data()).unwrap()
}

fn with_unlock(tx: &TransactionView, unlock: RGBPPUnlock) -> TransactionView {
    let witness = WitnessArgs::new_builder()
        .lock(Some(unlock.as_bytes()).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build()
}

// Recommit a deliberately changed CKB transaction so output-seal validation is
// reached instead of failing earlier on an unrelated commitment mismatch.
fn recommit(scripts: &TestScripts, tx: &TransactionView) -> TransactionView {
    let witness = unlock(tx);
    let mut btc =
        parse_btc_tx(&witness.btc_tx().raw_data()).unwrap_or_else(|_| panic!("fixture BTC"));
    btc.outputs[0] = TxOut::new_seal(500, gen_commitment(scripts, tx, &witness.extra_data()));
    let raw = encode_btc_tx(btc);
    let txid = sha2(&sha2(&raw)).pack();
    let outputs = tx
        .outputs()
        .into_iter()
        .map(|cell| set_cell_btc_txid(scripts, cell, txid.clone()))
        .collect();
    let tx = tx.as_advanced_builder().set_outputs(outputs).build();
    with_unlock(&tx, witness.as_builder().btc_tx(raw.pack()).build())
}

#[test]
fn input_seal_requires_both_transaction_id_and_output_index() {
    let (context, _, tx) = fixture(false);
    for change_txid in [true, false] {
        let witness = unlock(&tx);
        let mut btc =
            parse_btc_tx(&witness.btc_tx().raw_data()).unwrap_or_else(|_| panic!("fixture BTC"));
        if change_txid {
            btc.inputs[0].previous_output.0 = [0x42; 32].pack();
        } else {
            btc.inputs[0].previous_output.1 += 1;
        }
        let changed = with_unlock(
            &tx,
            witness
                .as_builder()
                .btc_tx(encode_btc_tx(btc).pack())
                .build(),
        );
        // This check precedes SPV, commitment, and new-output seal checks.
        fails(&context, &changed, Error::UtxoSealMismatch);
    }
}

#[test]
fn rgbpp_output_seal_rejects_wrong_txid_even_when_commitment_matches() {
    let (context, _, tx) = fixture(false);
    let output = tx.outputs().get(0).unwrap();
    let lock = output.lock();
    let args = RGBPPLock::from_slice(&lock.args().raw_data())
        .unwrap()
        .as_builder()
        .btc_txid([0x42; 32].pack())
        .build();
    let output = output
        .as_builder()
        .lock(lock.as_builder().args(args.as_bytes().pack()).build())
        .build();
    let changed = tx.as_advanced_builder().set_outputs(vec![output]).build();
    // btc_txid is zeroed for commitment hashing; verify_outputs must reject it.
    fails(&context, &changed, Error::OutputCellWithUnknownLock);
}

#[test]
fn rgbpp_output_seal_index_boundary_is_checked_after_commitment() {
    let (context, scripts, tx) = fixture(false);
    for index in [1u32, 2, u32::MAX] {
        let output = tx.outputs().get(0).unwrap();
        let lock = output.lock();
        let args = RGBPPLock::from_slice(&lock.args().raw_data())
            .unwrap()
            .as_builder()
            .out_index(index.pack())
            .build();
        let output = output
            .as_builder()
            .lock(lock.as_builder().args(args.as_bytes().pack()).build())
            .build();
        let changed = recommit(
            &scripts,
            &tx.as_advanced_builder().set_outputs(vec![output]).build(),
        );
        if index == 1 {
            passes(&context, &changed);
        } else {
            fails(&context, &changed, Error::OutputCellWithUnknownLock);
        }
    }
}

#[test]
fn commitment_authenticates_output_data_and_length() {
    let (context, _, tx) = fixture(false);
    for data in [999u128.to_le_bytes().to_vec(), vec![0; 17]] {
        let changed = tx
            .as_advanced_builder()
            .set_outputs_data(vec![data.pack()])
            .build();
        fails(&context, &changed, Error::CommitmentMismatch);
    }
}

#[test]
fn commitment_authenticates_ckb_input_outpoint() {
    let (mut context, _, tx) = fixture(false);
    let (cell, data) = context
        .get_cell(&tx.inputs().get(0).unwrap().previous_output())
        .unwrap();
    let replacement = context.create_cell(cell, data);
    let changed = tx
        .as_advanced_builder()
        .set_inputs(vec![CellInput::new_builder()
            .previous_output(replacement)
            .build()])
        .build();
    fails(&context, &changed, Error::CommitmentMismatch);
}

#[test]
fn commitment_allows_untyped_suffix_but_never_uncommitted_assets() {
    let (mut context, _, tx) = fixture(false);
    for typed in [false, true] {
        let original = tx.outputs().get(0).unwrap();
        let suffix = if typed {
            original.clone()
        } else {
            original
                .clone()
                .as_builder()
                .type_(ScriptOpt::default())
                .build()
        };
        let changed = tx
            .as_advanced_builder()
            .output(suffix)
            .output_data(0u128.to_le_bytes().to_vec().pack())
            .build();
        if typed {
            fails(&context, &changed, Error::CommitmentMismatch);
        } else {
            passes(&context, &changed);
        }

        let (input, _) = context
            .get_cell(&tx.inputs().get(0).unwrap().previous_output())
            .unwrap();
        let suffix = if typed {
            input
        } else {
            input.as_builder().type_(ScriptOpt::default()).build()
        };
        let point = context.create_cell(suffix, 0u128.to_le_bytes().to_vec().into());
        let changed = tx
            .as_advanced_builder()
            .input(CellInput::new_builder().previous_output(point).build())
            .build();
        if typed {
            fails(&context, &changed, Error::CommitmentMismatch);
        } else {
            passes(&context, &changed);
        }
    }
}

#[test]
fn commitment_rejects_unknown_version_and_empty_committed_prefix() {
    let (context, _, tx) = fixture(false);
    let witness = unlock(&tx);
    fails(
        &context,
        &with_unlock(
            &tx,
            witness.clone().as_builder().version(1u16.pack()).build(),
        ),
        Error::UnknownCommitmentVersion,
    );
    for input in [true, false] {
        let extra = witness.extra_data().as_builder();
        let extra = if input {
            extra.input_len(0u8.into())
        } else {
            extra.output_len(0u8.into())
        }
        .build();
        fails(
            &context,
            &with_unlock(&tx, witness.clone().as_builder().extra_data(extra).build()),
            Error::BadBtcCommitment,
        );
    }
}

#[test]
fn indexed_witness_errors_do_not_fall_back_to_other_witnesses() {
    let (context, _, tx) = fixture(false);
    let original = tx.witnesses().get(0).unwrap();
    let pointer = |index: u32| {
        WitnessArgs::new_builder()
            .lock(Some(Bytes::copy_from_slice(&index.to_le_bytes())).pack())
            .build()
            .as_bytes()
            .pack()
    };
    let missing = WitnessArgs::default().as_bytes().pack();
    let malformed = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8])).pack())
        .build()
        .as_bytes()
        .pack();
    for (witnesses, error) in [
        (vec![pointer(1), original.clone()], None),
        (
            vec![pointer(2), original.clone()],
            Some(Error::IndexOutOfBound),
        ),
        (vec![pointer(1), missing], Some(Error::ItemMissing)),
        (vec![pointer(1), malformed], Some(Error::BadRGBPPUnlock)),
        (vec![pointer(0), original], Some(Error::BadRGBPPUnlock)),
    ] {
        let changed = tx.as_advanced_builder().set_witnesses(witnesses).build();
        match error {
            Some(error) => fails(&context, &changed, error),
            None => passes(&context, &changed),
        }
    }
}

#[test]
fn time_lock_preserves_capacity_and_type() {
    let (context, _, tx) = fixture(true);
    let output = tx.outputs().get(0).unwrap();
    for changed_output in [
        output.clone().as_builder().capacity(1u64.pack()).build(),
        output.as_builder().type_(ScriptOpt::default()).build(),
    ] {
        let changed = tx
            .as_advanced_builder()
            .set_outputs(vec![changed_output])
            .build();
        fails(&context, &changed, Error::OutputCellMismatch);
    }
}

#[test]
fn time_lock_matches_each_group_input_at_its_absolute_output_index() {
    let (mut context, scripts, tx) = fixture(true);
    let (cell, _) = context
        .get_cell(&tx.inputs().get(0).unwrap().previous_output())
        .unwrap();
    let point = context.create_cell(cell, 500u128.to_le_bytes().to_vec().into());
    // An unrelated input before the time-lock group makes group indices differ
    // from absolute transaction indices. Both time-locked cells share one lock.
    let unrelated = CellOutput::new_builder()
        .lock(
            Script::new_builder()
                .code_hash(scripts.btc_spv.btc_lc_type_hash.clone())
                .hash_type(1u8.into())
                .build(),
        )
        .build();
    let unrelated_point = context.create_cell(unrelated.clone(), Default::default());
    let tx = tx
        .as_advanced_builder()
        .set_inputs(vec![
            CellInput::new_builder()
                .previous_output(unrelated_point)
                .build(),
            tx.inputs().get(0).unwrap(),
            CellInput::new_builder().previous_output(point).build(),
        ])
        .set_outputs(vec![
            unrelated,
            tx.outputs().get(0).unwrap(),
            tx.outputs().get(0).unwrap(),
        ])
        .set_outputs_data(vec![
            Vec::<u8>::new().pack(),
            1000u128.to_le_bytes().to_vec().pack(),
            500u128.to_le_bytes().to_vec().pack(),
        ])
        .set_witnesses(vec![
            WitnessArgs::default().as_bytes().pack(),
            tx.witnesses().get(0).unwrap(),
        ])
        .build();
    let tx = context.complete_tx(tx);
    passes(&context, &tx);
    // Same total amount, but swapped per-cell data must not be accepted.
    let swapped = tx
        .as_advanced_builder()
        .set_outputs_data(vec![
            Vec::<u8>::new().pack(),
            500u128.to_le_bytes().to_vec().pack(),
            1000u128.to_le_bytes().to_vec().pack(),
        ])
        .build();
    fails_at(&context, &swapped, Error::OutputCellMismatch, 1);
    let missing = tx
        .as_advanced_builder()
        .set_outputs(tx.outputs().into_iter().take(2).collect())
        .set_outputs_data(tx.outputs_data().into_iter().take(2).collect())
        .build();
    fails_at(&context, &missing, Error::IndexOutOfBound, 1);
}
