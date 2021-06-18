///
/// Compares two values for equality in constant time based on the input
///
/// Panics if `a.len()!=b.len()`
///
/// ## Examples
///
/// Compare two byte arrays for equality:
/// ```
/// let x = [0,1,2,3,4,5,6,7,8];
/// let y = [0,1,2,3,4,5,6,7,8];
/// assert!(lc_crypto::cmp::eq(&x,&y))
/// ```
///
/// Compare two byte arrays for equality:
/// ```
/// let x = [0,1,2,3,4,5,6,7,8];
/// let y = [0,1,2,3,4,5,6,7,9];
/// assert!(!lc_crypto::cmp::eq(&x,&y))
/// ```
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    let mut ret = true;
    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        // SAFETY:
        // 0<=i<a.len()
        // a.len()==b.len()
        ret = ret & unsafe { a.get_unchecked(i) == b.get_unchecked(i) };
    }
    ret
}

#[cfg(test)]
mod test {
    #[test]
    pub fn test_eq_eq() {
        let x = [0, 1, 2, 3];
        let y = [0, 1, 2, 3];
        assert!(super::eq(&x, &y));
    }

    #[test]
    pub fn test_eq_ne() {
        let x = [0, 1, 2, 3];
        let y = [0, 1, 2, 4];
        assert!(!super::eq(&x, &y));
    }

    #[test]
    #[should_panic]
    pub fn test_diff_sizes0() {
        let x = [0, 1, 2];
        let y = [0, 1, 2, 4];
        super::eq(&x, &y);
    }

    #[test]
    #[should_panic]
    pub fn test_diff_sizes1() {
        let x = [0, 1, 2, 3];
        let y = [0, 1, 2];
        super::eq(&x, &y);
    }
}
