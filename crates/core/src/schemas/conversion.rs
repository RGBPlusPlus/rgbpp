use super::ckb_gen_types::prelude::*;
use super::rgbpp::*;
use molecule::bytes::Bytes;

impl Pack<Uint16> for u16 {
    fn pack(&self) -> Uint16 {
        Uint16::new_unchecked(Bytes::from(self.to_le_bytes().to_vec()))
    }
}

impl<'r> Unpack<u16> for Uint16Reader<'r> {
    fn unpack(&self) -> u16 {
        let mut b = [0u8; 2];
        b.copy_from_slice(self.as_slice());
        u16::from_le_bytes(b)
    }
}

impl Unpack<u16> for Uint16 {
    fn unpack(&self) -> u16 {
        self.as_reader().unpack()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint16_encoding_is_little_endian() {
        let packed: Uint16 = 0x1234u16.pack();
        assert_eq!(packed.as_slice(), &[0x34, 0x12]);
        let entity: u16 = packed.unpack();
        let reader: u16 = packed.as_reader().unpack();
        assert_eq!(entity, 0x1234);
        assert_eq!(reader, entity);
    }

    #[test]
    fn uint16_entity_and_reader_roundtrip_every_value() {
        for value in u16::MIN..=u16::MAX {
            let packed: Uint16 = value.pack();
            assert_eq!(packed.as_slice(), &value.to_le_bytes());
            let entity: u16 = packed.unpack();
            let reader: u16 = packed.as_reader().unpack();
            assert_eq!(entity, value);
            assert_eq!(reader, value);
        }
    }
}
