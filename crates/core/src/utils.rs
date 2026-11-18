use ckb_gen_types::packed::Script;

pub fn is_script_code_equal(a: &Script, b: &Script) -> bool {
    a.code_hash() == b.code_hash() && a.hash_type() == b.hash_type()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_gen_types::{core::ScriptHashType, prelude::*};

    #[test]
    fn script_code_identity_does_not_include_args() {
        let a = Script::new_builder()
            .code_hash([0x11; 32].pack())
            .hash_type(ScriptHashType::Type.into())
            .args(alloc::vec![1, 2].pack())
            .build();
        let b = a
            .clone()
            .as_builder()
            .args(alloc::vec![3, 4].pack())
            .build();
        assert!(is_script_code_equal(&a, &b));
        assert!(is_script_code_equal(&b, &a));
    }

    #[test]
    fn script_code_identity_includes_hash_and_hash_type() {
        let a = Script::new_builder()
            .code_hash([0x11; 32].pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let other_hash = a.clone().as_builder().code_hash([0x22; 32].pack()).build();
        let other_type = a
            .clone()
            .as_builder()
            .hash_type(ScriptHashType::Data.into())
            .build();
        assert!(is_script_code_equal(&a, &a));
        assert!(!is_script_code_equal(&a, &other_hash));
        assert!(!is_script_code_equal(&a, &other_type));
    }
}
