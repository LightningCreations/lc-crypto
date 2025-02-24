mod asm;

pub fn bytes_eq_secure(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(
        a.len(),
        b.len(),
        "Arguments to `bytes_eq_secure` must have the same length"
    );

    unsafe { asm::eq_bytes_secure_impl(a.as_ptr(), b.as_ptr(), a.len()) }
}

#[cfg(test)]
mod test {
    use super::bytes_eq_secure;

    #[test]
    fn test_bytes_eq_secure_eq() {
        assert!(bytes_eq_secure(&[], &[]));
        assert!(bytes_eq_secure(&[0], &[0]));
        assert!(bytes_eq_secure(&[42], &[42]));
        assert!(bytes_eq_secure(&[0, 1], &[0, 1]));
        assert!(bytes_eq_secure(&[0, 1, 2], &[0, 1, 2]));
        assert!(bytes_eq_secure(&[0, 1, 2, 3], &[0, 1, 2, 3]));
        assert!(bytes_eq_secure(&[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5]));
        assert!(bytes_eq_secure(
            &[1, 2, 3, 4, 5, 6, 7],
            &[1, 2, 3, 4, 5, 6, 7]
        ));
        assert!(bytes_eq_secure(
            &[0, 1, 2, 3, 4, 5, 6, 7],
            &[0, 1, 2, 3, 4, 5, 6, 7]
        ));
        assert!(bytes_eq_secure(
            &[0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            &[0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7]
        ));

        assert!(bytes_eq_secure(
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3,
                4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7
            ],
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3,
                4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7
            ]
        ));
    }

    #[test]
    fn test_bytes_eq_secure_ne() {
        assert!(!bytes_eq_secure(&[0], &[1]));
        assert!(!bytes_eq_secure(&[0, 1], &[1, 0]));
        assert!(!bytes_eq_secure(
            &[1, 2, 3, 4, 5, 6, 7],
            &[1, 2, 3, 4, 5, 6, 8]
        ));
    }

    #[test]
    #[should_panic]
    fn test_bytes_eq_secure_unequal_len() {
        let _ = bytes_eq_secure(&[], &[0]);
    }
}
