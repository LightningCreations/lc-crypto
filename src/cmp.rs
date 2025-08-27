use crate::asm;

#[inline]
pub fn bytes_eq_secure(a: &[u8], b: &[u8]) -> bool {
    checked_bytes_eq_secure(a, b)
        .ok()
        .expect("Parameters must have the same length")
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadLengthError;

impl core::fmt::Display for BadLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Arguments must have equal lengths")
    }
}

#[inline]
pub fn checked_bytes_eq_secure(a: &[u8], b: &[u8]) -> Result<bool, BadLengthError> {
    if a.len() != b.len() {
        Err(BadLengthError)
    } else {
        Ok(unsafe { asm::eq_bytes_secure(a.as_ptr(), b.as_ptr(), a.len()) })
    }
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
