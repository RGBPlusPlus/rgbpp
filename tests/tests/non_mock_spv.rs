//! Offline CKB-VM integration of production locks and their real SPV verifier.
//!
//! These are isolated easy-target chains rooted at a trusted regtest checkpoint,
//! not public Bitcoin transactions or a test of SPV type-script state admission.
//! Client updates are checked by the host verifier while constructing fixtures;
//! transaction inclusion, cell-dep lookup and lock semantics run inside CKB-VM.
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

fn proof_for(raw_tx: &[u8], wrong_merkle_root: bool) -> (spv::SpvClient, spv::TransactionProof) {
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
    block.header.time += 1;
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
    for height in 1..=CONFIRMATIONS + 1 {
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
        .headers(spv_traits::Pack::pack(&headers))
        .new_headers_mmr_proof(
            spv::MmrProof::new_builder()
                .set(
                    mmr.gen_proof(positions.clone())
                        .unwrap()
                        .proof_items()
                        .to_vec(),
                )
                .build(),
        )
        .build();
    checkpoint
        .verify_new_client(&client, update, 0)
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
    (client, proof)
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
    // Never fall back to build/release: that directory contains mock binaries in
    // the existing suite. The non-mock CI job builds this directory separately.
    let loader = Loader::from_dir(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/non-mock"),
    );
    let mut context = Context::default();
    let spv_type = random_type_id_script();
    let spv_cell = context.create_cell(
        CellOutput::new_builder()
            .type_(Some(spv_type.clone()).pack())
            .build(),
        Bytes::new(),
    );
    let scripts = utils::TestScripts {
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
    let (client, proof) = proof_for(&raw_tx, false);
    let (cell, _) = context.get_cell(&spv_cell).unwrap();
    context.create_cell_with_out_point(spv_cell.clone(), cell, client.as_bytes());
    let tx = with_proof(&tx, kind, proof.as_bytes())
        .as_advanced_builder()
        .cell_dep(CellDep::new_builder().out_point(spv_cell).build())
        .build();
    let tx = context.complete_tx(tx);
    let fixture = Fixture {
        context,
        scripts,
        tx,
        proof,
        client,
        raw_tx,
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
        let (client, proof) = proof_for(&f.raw_tx, true);
        f.replace_client(client.as_bytes());
        f.fails(
            &with_proof(&f.tx, kind, proof.as_bytes()),
            Error::SpvProofIncorrect,
        );
    }
}
