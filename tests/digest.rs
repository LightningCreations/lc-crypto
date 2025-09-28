#![feature(macro_metavar_expr_concat)]

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use lc_crypto::digest::{
    RawDigest,
    raw::{
        sha1::Sha1,
        sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256},
        sha3::Sha3_256,
    },
};
use lc_crypto::traits::ByteArray;

const BASE_PATH: &str = core::env!("CARGO_MANIFEST_DIR");

fn test_digest<D: RawDigest + Default>(path: &Path) -> std::io::Result<()> {
    let mut file = BufReader::new(std::fs::File::open(path)?);
    let mut base_path = PathBuf::from(BASE_PATH);
    base_path.push("tests/digest");
    for line in file.lines() {
        let line = line?;
        let (hex, path) = line.split_once(|w: char| w.is_ascii_whitespace()).unwrap();
        let path = path.trim_ascii().trim_start_matches('*');
        let hash = D::Output::from_hex_string(hex).expect(hex);
        let mut new_path = base_path.clone();
        new_path.push(path);
        let bytes = std::fs::read(new_path)?;
        let output = lc_crypto::digest::digest(D::default(), &bytes).unwrap();
        assert_eq!(output, hash);
    }
    Ok(())
}

macro_rules! mk_hash_test {
    ($(#[$meta:meta])* $hash_name:ident => $ty:ty) => {
        $(#[$meta])*
        #[test]
        fn ${concat(test_, $hash_name)}() {
            let path = Path::new(::core::concat!(::core::env!("CARGO_MANIFEST_DIR"),"/tests/digest/answers/", ::core::stringify!($hash_name)));
            test_digest::<$ty>(path).expect(::core::concat!("answers/", ::core::stringify!($hash_name)));
        }
    };
}

mk_hash_test!(#[allow(deprecated)] sha1 => Sha1);
mk_hash_test!(sha224 => Sha224);
mk_hash_test!(sha256 => Sha256);
mk_hash_test!(sha384 => Sha384);
mk_hash_test!(sha512 => Sha512);
mk_hash_test!(sha512_224 => Sha512_224);
mk_hash_test!(sha512_256 => Sha512_256);

// mk_hash_test!(sha3_256 => Sha3_256);
