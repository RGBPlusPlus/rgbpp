use super::*;
use alloc::vec::Vec;
use ckb_gen_types::{bytes::Bytes, packed::Byte32};
pub use sha2::Digest;

pub struct TxIn {
    pub previous_output: (Byte32, u32),
    pub script: Bytes,
    pub sequence: u32,
}
pub struct TxOut {
    pub value: i64,
    pub script: Bytes,
}

impl TxOut {
    pub fn new_seal(value: i64, message: [u8; 32]) -> Self {
        let mut script = [0u8; 34];
        script[0] = OP_RETURN;
        script[1] = OP_PUSHBYTES_32;
        script[2..].copy_from_slice(&message);
        TxOut {
            value,
            script: script.to_vec().into(),
        }
    }
}

pub struct BTCTx {
    pub txid: Byte32,
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_output_preserves_value_and_message() {
        let message = [0x42; 32];
        let output = TxOut::new_seal(1234, message);
        assert_eq!(output.value, 1234);
        assert_eq!(output.script.len(), 34);
        assert_eq!(&output.script[..2], &[0x6a, 0x20]);
        assert_eq!(&output.script[2..], &message);
    }
}
