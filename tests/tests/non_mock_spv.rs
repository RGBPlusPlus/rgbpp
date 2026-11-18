//! Offline CKB-VM integration of production locks and their real SPV verifier.
//!
//! These are isolated easy-target chains rooted at a trusted regtest checkpoint,
//! not public Bitcoin transactions or a test of initial checkpoint admission.
//! Snapshot tests check client updates on the host; composed cases also validate
//! the SPV type-script update in CKB-VM before publishing its output for the locks.
//! Transaction inclusion, cell-dep lookup and lock semantics run inside CKB-VM.
use bitcoin::{
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    Network,
};
use ckb_bitcoin_spv_verifier::{
    types::{core as spv_core, packed as spv, prelude as spv_traits},
    utilities::mmr::{lib::util::MemStore, ClientRootMMR},
};
use ckb_testtool::{
    ckb_script::{ScriptError, TransactionScriptError},
    ckb_types::{bytes::Bytes, core::TransactionView, packed::*, prelude::*},
    context::{random_type_id_script, Context},
};
use rgbpp_core::{
    error::Error,
    schemas::rgbpp::{BTCTimeLock, BTCTimeUnlock, RGBPPUnlock},
};
use tests::Loader;

// Reuse transaction/config setup, not a mock verifier or mock SPV client.
#[allow(dead_code)]
#[path = "../src/btc_mock.rs"]
mod btc_mock;
#[allow(dead_code)]
#[path = "../src/rgbpp.rs"]
mod rgbpp;
#[allow(dead_code)]
#[path = "../src/utils.rs"]
mod utils;

const MAX_CYCLES: u64 = 20_000_000;
const CONFIRMATIONS: u32 = 6;

#[derive(Clone, Copy)]
enum Lock {
    Rgbpp,
    BtcTime,
}

struct Fixture {
    context: Context,
    scripts: utils::TestScripts,
    tx: TransactionView,
    proof: spv::TransactionProof,
    client: spv::SpvClient,
    raw_tx: Vec<u8>,
    transition: Option<ClientTransition>,
}

fn mine(mut header: spv_core::Header) -> spv_core::Header {
    for nonce in 0..10_000 {
        header.nonce = nonce;
        if header.validate_pow(header.target()).is_ok() {
            return header;
        }
    }
    panic!("bounded easy-target fixture generation failed");
}

fn proof_for(
    raw_tx: &[u8],
    wrong_merkle_root: bool,
) -> (
    spv::SpvClient,
    spv::TransactionProof,
    spv::SpvClient,
    spv::SpvUpdate,
) {
    branch_proof(raw_tx, wrong_merkle_root, 0, CONFIRMATIONS + 1, 0)
}

// Branches differ at height 1; start_height selects an already accepted prefix.
fn branch_proof(
    raw_tx: &[u8],
    wrong_merkle_root: bool,
    time_offset: u32,
    end_height: u32,
    start_height: u32,
) -> (
    spv::SpvClient,
    spv::TransactionProof,
    spv::SpvClient,
    spv::SpvUpdate,
) {
    let genesis = genesis_block(Network::Regtest);
    let checkpoint = spv::SpvBootstrap::new_builder()
        .height(spv_traits::Pack::pack(&0u32))
        .header(spv_traits::Pack::pack(&genesis.header))
        .build()
        .initialize_spv_client()
        .unwrap_or_else(|e| panic!("bootstrap {}", e as i8));
    let checkpoint: spv::SpvClient = spv_traits::Pack::pack(&checkpoint);
    let mut block = genesis.clone();
    block.txdata = vec![deserialize(raw_tx).expect("fixture Bitcoin transaction")];
    block.header.prev_blockhash = genesis.block_hash();
    block.header.time += 1 + time_offset;
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    if wrong_merkle_root {
        block.header.merkle_root = bitcoin::TxMerkleNode::from_raw_hash(
            <spv_core::Hash as spv_traits::Hash>::hash(b"unrelated transaction root"),
        );
    }
    block.header = mine(block.header);
    let merkle = spv_core::MerkleBlock::from_block_with_predicate(&block, |_| true);

    let store = MemStore::default();
    let mut mmr = ClientRootMMR::new(0, &store);
    mmr.push(checkpoint.headers_mmr_root()).unwrap();
    let mut header = block.header;
    let mut headers = Vec::new();
    let mut positions = Vec::new();
    let mut prefix = checkpoint.clone();
    for height in 1..=end_height {
        if height > 1 {
            header.prev_blockhash = header.block_hash();
            header.time += 1;
            header = mine(header);
        }
        positions.push(
            mmr.push(spv_traits::Pack::pack(&spv_core::HeaderDigest::new_leaf(
                height, &header,
            )))
            .unwrap(),
        );
        headers.push(header);
        if height == start_height {
            prefix = checkpoint
                .clone()
                .as_builder()
                .headers_mmr_root(mmr.get_root().unwrap())
                .tip_block_hash(spv_traits::Pack::pack(&spv_core::Hash::from(
                    header.block_hash(),
                )))
                .build();
        }
    }
    mmr.commit().unwrap();
    let client = checkpoint
        .clone()
        .as_builder()
        .headers_mmr_root(mmr.get_root().unwrap())
        .tip_block_hash(spv_traits::Pack::pack(&spv_core::Hash::from(
            header.block_hash(),
        )))
        .build();
    let update = spv::SpvUpdate::new_builder()
        .headers(spv_traits::Pack::pack(
            &headers[start_height as usize..].to_vec(),
        ))
        .new_headers_mmr_proof(
            spv::MmrProof::new_builder()
                .set(
                    mmr.gen_proof(positions[start_height as usize..].to_vec())
                        .unwrap()
                        .proof_items()
                        .to_vec(),
                )
                .build(),
        )
        .build();
    prefix
        .verify_new_client(&client, update.clone(), 0)
        .unwrap_or_else(|e| panic!("fixture client update {}", e as i8));
    let proof = spv::TransactionProof::new_builder()
        .height(spv_traits::Pack::pack(&1u32))
        .tx_index(spv_traits::Pack::pack(&0u32))
        .transaction_proof(spv_traits::Pack::pack(&spv_core::Bytes::from(serialize(
            &merkle,
        ))))
        .header_proof(
            spv::MmrProof::new_builder()
                .set(
                    mmr.gen_proof(vec![positions[0]])
                        .unwrap()
                        .proof_items()
                        .to_vec(),
                )
                .build(),
        )
        .build();
    (client, proof, prefix, update)
}

fn witness(tx: &TransactionView) -> WitnessArgs {
    WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap()
}

fn with_proof(tx: &TransactionView, kind: Lock, proof: Bytes) -> TransactionView {
    let witness = witness(tx);
    let lock = witness.lock().to_opt().unwrap().raw_data();
    let lock = match kind {
        Lock::Rgbpp => RGBPPUnlock::from_slice(&lock)
            .unwrap()
            .as_builder()
            .btc_tx_proof(proof.pack())
            .build()
            .as_bytes(),
        Lock::BtcTime => BTCTimeUnlock::from_slice(&lock)
            .unwrap()
            .as_builder()
            .btc_tx_proof(proof.pack())
            .build()
            .as_bytes(),
    };
    tx.as_advanced_builder()
        .set_witnesses(vec![witness
            .as_builder()
            .lock(Some(lock).pack())
            .build()
            .as_bytes()
            .pack()])
        .build()
}

fn fixture(kind: Lock) -> Fixture {
    fixture_with_update(kind, false)
}

fn fixture_with_update(kind: Lock, verify_update_in_vm: bool) -> Fixture {
    // Never fall back to build/release: that directory contains mock binaries in
    // the existing suite. The non-mock CI job builds this directory separately.
    let loader = Loader::from_dir(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/non-mock"),
    );
    let mut context = Context::default();
    let spv_type = if verify_update_in_vm {
        let code = context.deploy_cell(loader.load_binary("ckb-bitcoin-spv-type-lock"));
        let args = spv::SpvTypeArgs::new_builder()
            .clients_count(3u8.into())
            .build();
        context.build_script(&code, args.as_bytes()).unwrap()
    } else {
        random_type_id_script()
    };
    let spv_cell = context.create_cell(
        CellOutput::new_builder()
            .type_(Some(spv_type.clone()).pack())
            .build(),
        Bytes::new(),
    );
    let mut scripts = utils::TestScripts {
        app: utils::deploy_rgbpp_scripts(&loader, &mut context, spv_type.calc_script_hash()),
        sudt: utils::deploy_sudt_scripts(&loader, &mut context),
        btc_spv: utils::BTCLCScripts {
            btc_lc: spv_cell.clone(),
            btc_lc_type_hash: spv_type.calc_script_hash(),
        },
    };
    let desc = vec![rgbpp::OutputDesc {
        lock: match kind {
            Lock::Rgbpp => rgbpp::LockDesc::Rgbpp,
            Lock::BtcTime => rgbpp::LockDesc::UserLock(Default::default()),
        },
        amount: 1000,
    }];
    let tx = match kind {
        Lock::Rgbpp => rgbpp::build_rgbpp_tx(&mut context, &scripts, 1000, desc),
        Lock::BtcTime => rgbpp::build_btc_time_lock_tx(&mut context, &scripts, 1000, desc),
    };
    let raw_tx = match kind {
        Lock::Rgbpp => RGBPPUnlock::from_slice(&witness(&tx).lock().to_opt().unwrap().raw_data())
            .unwrap()
            .btc_tx()
            .raw_data()
            .to_vec(),
        Lock::BtcTime => serialize(&genesis_block(Network::Regtest).txdata[0]),
    };
    if let Lock::BtcTime = kind {
        let input = tx.inputs().get(0).unwrap().previous_output();
        let (cell, data) = context.get_cell(&input).unwrap();
        let lock = cell.lock();
        let args = BTCTimeLock::from_slice(&lock.args().raw_data())
            .unwrap()
            .as_builder()
            .btc_txid(rgbpp_core::bitcoin::sha2(&rgbpp_core::bitcoin::sha2(&raw_tx)).pack())
            .after(CONFIRMATIONS.pack())
            .build();
        context.create_cell_with_out_point(
            input,
            cell.as_builder()
                .lock(lock.as_builder().args(args.as_bytes().pack()).build())
                .build(),
            data,
        );
    }
    let (mut client, proof, checkpoint, update) = proof_for(&raw_tx, false);
    let transition = if verify_update_in_vm {
        client = client.as_builder().id(1u8.into()).build();
        let transition = client_transition(
            &mut context,
            &loader,
            &spv_type,
            checkpoint,
            &client,
            update,
        );
        let output = apply_client_update(&mut context, &transition.tx)
            .expect("SPV type-script update passes in VM");
        scripts.btc_spv.btc_lc = output;
        Some(transition)
    } else {
        let (cell, _) = context.get_cell(&spv_cell).unwrap();
        context.create_cell_with_out_point(spv_cell.clone(), cell, client.as_bytes());
        None
    };
    let tx = with_proof(&tx, kind, proof.as_bytes())
        .as_advanced_builder()
        .cell_dep(
            CellDep::new_builder()
                .out_point(scripts.btc_spv.btc_lc.clone())
                .build(),
        )
        .build();
    let tx = context.complete_tx(tx);
    let fixture = Fixture {
        context,
        scripts,
        tx,
        proof,
        client,
        raw_tx,
        transition,
    };
    fixture.passes(&fixture.tx);
    fixture
}

impl Fixture {
    fn passes(&self, tx: &TransactionView) {
        let cycles = self
            .context
            .verify_tx(tx, MAX_CYCLES)
            .expect("valid non-mock fixture");
        println!("non-mock contract cycles: {cycles}");
    }
    fn fails(&self, tx: &TransactionView, error: Error) {
        let input = tx.inputs().get(0).unwrap().previous_output();
        let (cell, _) = self.context.get_cell(&input).unwrap();
        let expected =
            ScriptError::validation_failure(&cell.lock(), error as i8).input_lock_script(0);
        let actual = self.context.verify_tx(tx, MAX_CYCLES).expect_err("invalid proof must fail in CKB-VM, including when checking for accidental mock binaries");
        assert_eq!(
            actual.root_cause().downcast_ref::<TransactionScriptError>(),
            Some(&expected)
        );
    }
    fn replace_client(&mut self, data: Bytes) {
        let out_point = self.scripts.btc_spv.btc_lc.clone();
        let (cell, _) = self.context.get_cell(&out_point).unwrap();
        self.context
            .create_cell_with_out_point(out_point, cell, data);
    }
}

#[test]
fn valid_merkle_and_mmr_proofs_pass_both_production_locks() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        fixture(kind);
    }
}

#[test]
fn malformed_proofs_reject_accidental_mock_binaries_for_both_locks() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let f = fixture(kind);
        f.fails(
            &with_proof(&f.tx, kind, Bytes::new()),
            Error::SpvProofMalformed,
        );
    }
}

#[test]
fn client_dependency_must_be_present_and_match_the_configured_type_hash() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let deps =
            f.tx.cell_deps()
                .into_iter()
                .filter(|dep| dep.out_point() != f.scripts.btc_spv.btc_lc)
                .collect();
        f.fails(
            &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
            Error::SpvClientNotFound,
        );
        let out_point = f.scripts.btc_spv.btc_lc.clone();
        let (cell, data) = f.context.get_cell(&out_point).unwrap();
        f.context.create_cell_with_out_point(
            out_point,
            cell.as_builder().type_(None::<Script>.pack()).build(),
            data,
        );
        f.fails(&f.tx, Error::SpvClientNotFound);
    }
}

#[test]
fn malformed_client_cells_are_rejected() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        f.replace_client(Bytes::from_static(&[0x42]));
        f.fails(&f.tx, Error::SpvClientMalformed);
    }
}

#[test]
fn merkle_membership_does_not_replace_header_mmr_membership() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let f = fixture(kind);
        let mut merkle: spv_core::MerkleBlock =
            deserialize(&f.proof.transaction_proof().raw_data()).unwrap();
        merkle.header.nonce ^= 1;
        let proof = f
            .proof
            .clone()
            .as_builder()
            .transaction_proof(spv_traits::Pack::pack(&spv_core::Bytes::from(serialize(
                &merkle,
            ))))
            .build();
        f.fails(
            &with_proof(&f.tx, kind, proof.as_bytes()),
            Error::SpvProofIncorrect,
        );
    }
}

#[test]
fn wrong_transaction_index_and_truncated_merkle_proof_are_rejected() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let f = fixture(kind);
        let bad_index = f
            .proof
            .clone()
            .as_builder()
            .tx_index(spv_traits::Pack::pack(&1u32))
            .build();
        f.fails(
            &with_proof(&f.tx, kind, bad_index.as_bytes()),
            Error::SpvProofIncorrect,
        );
        let bytes = f.proof.transaction_proof().raw_data();
        let truncated = f
            .proof
            .clone()
            .as_builder()
            .transaction_proof(spv_traits::Pack::pack(&spv_core::Bytes::from(
                bytes[..bytes.len() - 1].to_vec(),
            )))
            .build();
        f.fails(
            &with_proof(&f.tx, kind, truncated.as_bytes()),
            Error::SpvProofIncorrect,
        );
    }
}

#[test]
fn time_lock_enforces_confirmations_at_the_boundary() {
    let mut f = fixture(Lock::BtcTime); // exactly six confirmations succeeds
    let input = f.tx.inputs().get(0).unwrap().previous_output();
    let (cell, data) = f.context.get_cell(&input).unwrap();
    let lock = cell.lock();
    let args = BTCTimeLock::from_slice(&lock.args().raw_data())
        .unwrap()
        .as_builder()
        .after((CONFIRMATIONS + 1).pack())
        .build();
    f.context.create_cell_with_out_point(
        input,
        cell.as_builder()
            .lock(lock.as_builder().args(args.as_bytes().pack()).build())
            .build(),
        data,
    );
    f.fails(&f.tx, Error::SpvProofIncorrect);
}

#[test]
fn valid_spv_does_not_allow_a_different_rgbpp_commitment() {
    let f = fixture(Lock::Rgbpp);
    let output =
        f.tx.outputs()
            .get(0)
            .unwrap()
            .as_builder()
            .capacity(1u64.pack())
            .build();
    let changed = f.tx.as_advanced_builder().set_outputs(vec![output]).build();
    f.fails(&changed, Error::CommitmentMismatch);
}

#[test]
fn client_mmr_root_cannot_be_replaced_while_reusing_the_proof() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let root = f
            .client
            .headers_mmr_root()
            .as_builder()
            .children_hash(spv_traits::Pack::pack(
                &<spv_core::Hash as spv_traits::Hash>::hash(b"unrelated root"),
            ))
            .build();
        let client = f.client.clone().as_builder().headers_mmr_root(root).build();
        f.replace_client(client.as_bytes());
        f.fails(&f.tx, Error::SpvProofIncorrect);
    }
}

#[test]
fn proof_is_bound_to_the_transaction_requested_by_the_lock() {
    let f = fixture(Lock::Rgbpp);
    let args = witness(&f.tx);
    let unlock = RGBPPUnlock::from_slice(&args.lock().to_opt().unwrap().raw_data()).unwrap();
    let mut btc = rgbpp_core::bitcoin::parse_btc_tx(&unlock.btc_tx().raw_data())
        .unwrap_or_else(|_| panic!("fixture tx"));
    btc.outputs[1].value += 1;
    let unlock = unlock
        .as_builder()
        .btc_tx(rgbpp_core::bitcoin::encode_btc_tx(btc).pack())
        .build();
    let tx =
        f.tx.as_advanced_builder()
            .set_witnesses(vec![args
                .as_builder()
                .lock(Some(unlock.as_bytes()).pack())
                .build()
                .as_bytes()
                .pack()])
            .build();
    f.fails(&tx, Error::SpvProofIncorrect);

    let mut f = fixture(Lock::BtcTime);
    let input = f.tx.inputs().get(0).unwrap().previous_output();
    let (cell, data) = f.context.get_cell(&input).unwrap();
    let lock = cell.lock();
    let args = BTCTimeLock::from_slice(&lock.args().raw_data())
        .unwrap()
        .as_builder()
        .btc_txid([0x42; 32].pack())
        .build();
    f.context.create_cell_with_out_point(
        input,
        cell.as_builder()
            .lock(lock.as_builder().args(args.as_bytes().pack()).build())
            .build(),
        data,
    );
    f.fails(&f.tx, Error::SpvProofIncorrect);
}

#[test]
fn proof_height_must_be_inside_the_client_range() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let newer = f
            .proof
            .clone()
            .as_builder()
            .height(spv_traits::Pack::pack(&(CONFIRMATIONS + 2)))
            .build();
        f.fails(
            &with_proof(&f.tx, kind, newer.as_bytes()),
            Error::SpvProofIncorrect,
        );
        let root = f
            .client
            .headers_mmr_root()
            .as_builder()
            .min_height(spv_traits::Pack::pack(&2u32))
            .build();
        let client = f.client.clone().as_builder().headers_mmr_root(root).build();
        f.replace_client(client.as_bytes());
        f.fails(&f.tx, Error::SpvProofIncorrect);
    }
}

#[test]
fn merkle_root_must_match_the_transaction_proof() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        // Bind the client MMR to this changed header too: otherwise the MMR
        // check could mask a missing transaction-Merkle check.
        let (client, proof, _, _) = proof_for(&f.raw_tx, true);
        f.replace_client(client.as_bytes());
        f.fails(
            &with_proof(&f.tx, kind, proof.as_bytes()),
            Error::SpvProofIncorrect,
        );
    }
}

struct ClientTransition {
    tx: TransactionView,
    old_tip: OutPoint,
    type_script: Script,
}

// Start from an explicitly trusted checkpoint and the next client slot. Only
// the type script (not a node, network or operator's authorization lock) is under
// test here; always_success isolates the unrelated ownership lock.
fn client_transition(
    context: &mut Context,
    loader: &Loader,
    type_script: &Script,
    checkpoint: spv::SpvClient,
    client: &spv::SpvClient,
    update: spv::SpvUpdate,
) -> ClientTransition {
    let lock_code = context.deploy_cell(loader.load_tests_binary("always_success"));
    let lock = context.build_script(&lock_code, Bytes::new()).unwrap();
    let cell = CellOutput::new_builder()
        .capacity(500_0000_0000u64.pack())
        .lock(lock)
        .type_(Some(type_script.clone()).pack())
        .build();
    let old_tip = context.create_cell(cell.clone(), checkpoint.as_bytes());
    let input_info = context.create_cell(cell.clone(), spv::SpvInfo::default().as_bytes());
    let input_client = context.create_cell(
        cell.clone(),
        checkpoint.as_builder().id(1u8.into()).build().as_bytes(),
    );
    let output_info = spv::SpvInfo::new_builder()
        .tip_client_id(1u8.into())
        .build();
    let witness = WitnessArgs::new_builder()
        .output_type(Some(update.as_bytes()).pack())
        .build();
    let tx = Transaction::default()
        .as_advanced_builder()
        .inputs(vec![
            CellInput::new_builder().previous_output(input_info).build(),
            CellInput::new_builder()
                .previous_output(input_client)
                .build(),
        ])
        .outputs(vec![cell.clone(), cell])
        .outputs_data(vec![
            output_info.as_bytes().pack(),
            client.as_bytes().pack(),
        ])
        .cell_dep(CellDep::new_builder().out_point(old_tip.clone()).build())
        .witness(witness.as_bytes().pack())
        .build();
    ClientTransition {
        tx: context.complete_tx(tx),
        old_tip,
        type_script: type_script.clone(),
    }
}

fn apply_client_update(
    context: &mut Context,
    tx: &TransactionView,
) -> Result<OutPoint, ckb_testtool::ckb_error::Error> {
    let cycles = context.verify_tx(tx, MAX_CYCLES)?;
    println!("SPV type-script update cycles: {cycles}");
    // Materialize the exact verified output, never a separately injected copy.
    // In particular, failed updates cannot make their proposed client available.
    let out_point = OutPoint::new_builder()
        .tx_hash(tx.hash())
        .index(1u32.pack())
        .build();
    context.create_cell_with_out_point(
        out_point.clone(),
        tx.outputs().get(1).unwrap(),
        tx.outputs_data().get(1).unwrap().raw_data(),
    );
    Ok(out_point)
}

#[test]
fn vm_verified_client_update_is_consumed_by_both_rgbpp_locks() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let f = fixture_with_update(kind, true);
        let transition = f.transition.as_ref().unwrap();
        assert_eq!(f.scripts.btc_spv.btc_lc.tx_hash(), transition.tx.hash());
        assert_eq!(
            f.context.get_cell(&f.scripts.btc_spv.btc_lc).unwrap().1,
            transition.tx.outputs_data().get(1).unwrap().raw_data()
        );
        // The same proof must fail against the checkpoint and pass only after
        // the actual accepted update output is selected by the consuming lock.
        let deps =
            f.tx.cell_deps()
                .into_iter()
                .map(|dep| {
                    if dep.out_point() == f.scripts.btc_spv.btc_lc {
                        dep.as_builder()
                            .out_point(transition.old_tip.clone())
                            .build()
                    } else {
                        dep
                    }
                })
                .collect();
        f.fails(
            &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
            Error::SpvProofIncorrect,
        );
    }
}

#[test]
fn rejected_spv_update_does_not_publish_a_client_for_consumption() {
    let mut f = fixture_with_update(Lock::Rgbpp, true);
    let transition = f.transition.as_ref().unwrap();
    let bad_client = f
        .client
        .clone()
        .as_builder()
        .tip_block_hash(spv_traits::Pack::pack(
            &<spv_core::Hash as spv_traits::Hash>::hash(b"wrong tip"),
        ))
        .build();
    let bad_tx = transition
        .tx
        .as_advanced_builder()
        .set_outputs_data(vec![
            transition.tx.outputs_data().get(0).unwrap(),
            bad_client.as_bytes().pack(),
        ])
        .build();
    let expected = ScriptError::validation_failure(
        &transition.type_script,
        0x60 + ckb_bitcoin_spv_verifier::error::UpdateError::ClientTipBlockHash as i8,
    )
    .input_type_script(0);
    let error = apply_client_update(&mut f.context, &bad_tx)
        .expect_err("invalid client update rejected by actual SPV type script");
    assert_eq!(
        error.root_cause().downcast_ref::<TransactionScriptError>(),
        Some(&expected)
    );
    let proposed = OutPoint::new_builder()
        .tx_hash(bad_tx.hash())
        .index(1u32.pack())
        .build();
    assert!(f.context.get_cell(&proposed).is_none());
}

// Only materialize outputs after the complete type-script transition succeeds.
fn apply_transition(context: &mut Context, tx: &TransactionView) -> Vec<OutPoint> {
    context
        .verify_tx(tx, MAX_CYCLES)
        .expect("SPV transition passes in VM");
    tx.outputs()
        .into_iter()
        .zip(tx.outputs_data())
        .enumerate()
        .map(|(index, (cell, data))| {
            let out_point = OutPoint::new_builder()
                .tx_hash(tx.hash())
                .index((index as u32).pack())
                .build();
            context.create_cell_with_out_point(out_point.clone(), cell, data.raw_data());
            out_point
        })
        .collect()
}

#[test]
fn vm_verified_reorg_outputs_are_consumed_by_both_locks() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture_with_update(kind, true);
        let first = f.transition.as_ref().unwrap();
        let first_tx = first.tx.clone();
        let checkpoint_out = first.old_tip.clone();
        let first_outputs = apply_transition(&mut f.context, &first_tx);
        let template = first_tx.outputs().get(0).unwrap();
        let (_, checkpoint_data) = f.context.get_cell(&checkpoint_out).unwrap();
        let checkpoint = spv::SpvClient::from_slice(&checkpoint_data).unwrap();
        // Slot 2 is part of the explicitly trusted initial checkpoint state.
        let slot2 = f.context.create_cell(
            template.clone(),
            checkpoint
                .clone()
                .as_builder()
                .id(2u8.into())
                .build()
                .as_bytes(),
        );
        let (old_tip, old_proof, _, second_update) =
            branch_proof(&f.raw_tx, false, 0, CONFIRMATIONS + 2, CONFIRMATIONS + 1);
        let old_tip = old_tip.as_builder().id(2u8.into()).build();
        let second_tx = Transaction::default()
            .as_advanced_builder()
            .inputs(vec![
                CellInput::new_builder()
                    .previous_output(first_outputs[0].clone())
                    .build(),
                CellInput::new_builder().previous_output(slot2).build(),
            ])
            .outputs(vec![template.clone(), template.clone()])
            .outputs_data(vec![
                spv::SpvInfo::new_builder()
                    .tip_client_id(2u8.into())
                    .build()
                    .as_bytes()
                    .pack(),
                old_tip.as_bytes().pack(),
            ])
            .cell_dep(
                CellDep::new_builder()
                    .out_point(first_outputs[1].clone())
                    .build(),
            )
            .witness(
                WitnessArgs::new_builder()
                    .output_type(Some(second_update.as_bytes()).pack())
                    .build()
                    .as_bytes()
                    .pack(),
            )
            .build();
        let second_tx = f.context.complete_tx(second_tx);
        let second_outputs = apply_transition(&mut f.context, &second_tx);
        // Competing branch starts at the retained checkpoint and has strictly more work.
        let (new_tip, new_proof, _, reorg_update) =
            branch_proof(&f.raw_tx, false, 100, CONFIRMATIONS + 3, 0);
        let reorg_tx = Transaction::default()
            .as_advanced_builder()
            .inputs(
                vec![
                    second_outputs[0].clone(),
                    second_outputs[1].clone(),
                    first_outputs[1].clone(),
                ]
                .into_iter()
                .map(|out| CellInput::new_builder().previous_output(out).build())
                .collect::<Vec<_>>(),
            )
            .outputs(vec![template.clone(); 3])
            .outputs_data(vec![
                spv::SpvInfo::new_builder()
                    .tip_client_id(1u8.into())
                    .build()
                    .as_bytes()
                    .pack(),
                new_tip
                    .clone()
                    .as_builder()
                    .id(2u8.into())
                    .build()
                    .as_bytes()
                    .pack(),
                new_tip
                    .as_builder()
                    .id(1u8.into())
                    .build()
                    .as_bytes()
                    .pack(),
            ])
            .cell_dep(CellDep::new_builder().out_point(checkpoint_out).build())
            .witness(
                WitnessArgs::new_builder()
                    .output_type(Some(reorg_update.as_bytes()).pack())
                    .build()
                    .as_bytes()
                    .pack(),
            )
            .build();
        let reorg_tx = f.context.complete_tx(reorg_tx);
        let reorg_outputs = apply_transition(&mut f.context, &reorg_tx);
        let consumer = |proof: &spv::TransactionProof, client: &OutPoint| {
            let deps =
                f.tx.cell_deps()
                    .into_iter()
                    .map(|dep| {
                        if dep.out_point() == f.scripts.btc_spv.btc_lc {
                            dep.as_builder().out_point(client.clone()).build()
                        } else {
                            dep
                        }
                    })
                    .collect();
            with_proof(&f.tx, kind, proof.as_bytes())
                .as_advanced_builder()
                .set_cell_deps(deps)
                .build()
        };
        // The old proof is valid against the pre-reorg client, not a malformed fixture.
        f.passes(&consumer(&old_proof, &second_outputs[1]));
        f.fails(
            &consumer(&new_proof, &second_outputs[1]),
            Error::SpvProofIncorrect,
        );
        for client in &reorg_outputs[1..] {
            f.passes(&consumer(&new_proof, client));
            f.fails(&consumer(&old_proof, client), Error::SpvProofIncorrect);
        }
    }
}

fn config_out_point(f: &Fixture, kind: Lock) -> OutPoint {
    match kind {
        Lock::Rgbpp => f.scripts.app.rgbpp.config_out_point.clone(),
        Lock::BtcTime => f.scripts.app.btc_time_lock.config_out_point.clone(),
    }
}

#[test]
fn config_lookup_accepts_reordered_code_dependencies() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let f = fixture(kind);
        let mut deps: Vec<_> = f.tx.cell_deps().into_iter().collect();
        deps.reverse();
        f.passes(&f.tx.as_advanced_builder().set_cell_deps(deps).build());
    }
}

#[test]
fn config_lookup_requires_the_matching_deployment_output() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let config = config_out_point(&f, kind);
        let deps: Vec<_> =
            f.tx.cell_deps()
                .into_iter()
                .filter(|dep| dep.out_point() != config)
                .collect();
        f.fails(
            &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
            Error::ConfigNotFound,
        );
        let (cell, data) = f.context.get_cell(&config).unwrap();
        // Valid config bytes at the wrong output must not satisfy lookup.
        let wrong_output = config.clone().as_builder().index(2u32.pack()).build();
        f.context
            .create_cell_with_out_point(wrong_output.clone(), cell.clone(), data.clone());
        // Nor may an unrelated deployment's output 1 supply the config.
        let wrong_deployment = config
            .clone()
            .as_builder()
            .tx_hash([0x57u8; 32].pack())
            .build();
        f.context
            .create_cell_with_out_point(wrong_deployment.clone(), cell, data);
        for replacement in [wrong_output, wrong_deployment] {
            let deps: Vec<_> =
                f.tx.cell_deps()
                    .into_iter()
                    .map(|dep| {
                        if dep.out_point() == config {
                            dep.as_builder().out_point(replacement.clone()).build()
                        } else {
                            dep
                        }
                    })
                    .collect();
            f.fails(
                &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
                Error::ConfigNotFound,
            );
        }
    }
}

#[test]
fn config_lookup_rejects_malformed_config_data() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let config = config_out_point(&f, kind);
        let (cell, _) = f.context.get_cell(&config).unwrap();
        f.context
            .create_cell_with_out_point(config, cell, Bytes::from_static(&[0x42]));
        f.fails(&f.tx, Error::ConfigMalformed);
    }
}

#[test]
fn config_lookup_requires_code_and_config_before_dep_groups() {
    for kind in [Lock::Rgbpp, Lock::BtcTime] {
        let mut f = fixture(kind);
        let config = config_out_point(&f, kind);
        let (cell, _) = f.context.get_cell(&config).unwrap();
        let unrelated = f
            .context
            .create_cell(cell.clone(), Bytes::from_static(b"unrelated dependency"));
        let group_data = OutPointVec::new_builder()
            .push(unrelated)
            .build()
            .as_bytes();
        let group = f.context.create_cell(cell, group_data);
        let group_dep = CellDep::new_builder()
            .out_point(group)
            .dep_type(1u8.into())
            .build();
        let mut deps: Vec<_> = f.tx.cell_deps().into_iter().collect();
        deps.push(group_dep.clone());
        f.passes(&f.tx.as_advanced_builder().set_cell_deps(deps).build());
        let mut deps: Vec<_> = f.tx.cell_deps().into_iter().collect();
        deps.insert(0, group_dep.clone());
        f.fails(
            &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
            Error::ConfigNotFound,
        );
        // The code lookup succeeds here; the config lookup must separately reject
        // a config placed after a dep-group.
        let config_dep =
            f.tx.cell_deps()
                .into_iter()
                .find(|dep| dep.out_point() == config)
                .unwrap();
        let mut deps: Vec<_> =
            f.tx.cell_deps()
                .into_iter()
                .filter(|dep| dep.out_point() != config)
                .collect();
        deps.push(group_dep);
        deps.push(config_dep);
        f.fails(
            &f.tx.as_advanced_builder().set_cell_deps(deps).build(),
            Error::ConfigNotFound,
        );
    }
}
