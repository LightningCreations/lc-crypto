use bytemuck::TransparentWrapper;

use crate::traits::{SecretSlice, SecretTy};

/// A Raw number with arbitrary precision.
/// This value is an unsized type and thus can only be handled via indirections such as [`Box`] or `&RawBigNum`.
///
/// Note that only [`Eq`] and [`PartialEq`] (not [`Ord`] or [`PartialOrd`]) are implemented.
/// This is because [`SecretTy`] expects bytewise equality comparison to be valid, but [`RawBigNum`] has two notions of equality.
/// [`==`][PartialEq] for [`RawBigNum`] checks if the length of the two slices are equal and the value of each element. However
#[derive(TransparentWrapper, PartialEq, Eq)]
#[repr(transparent)]
pub struct RawBigNum([u8]);

unsafe impl SecretSlice for RawBigNum {
    type ElemTy = u8;
}

crate::secret_slice_wrap!(RawBigNum);

#[non_exhaustive]
#[derive(Debug)]
pub struct TryFromBigNumError;

macro_rules! impl_try_from_raw_bignum {
    ($($int_ty:ident),* $(,)?) => {
        $(
            impl TryFrom<&RawBigNum> for $int_ty {
                type Error = TryFromBigNumError;

                fn try_from(this: &RawBigNum) -> Result<Self, TryFromBigNumError> {
                    let mut val = 0 as Self;

                    for n in &this.0 {
                        val = val.checked_mul(0x100)
                            .ok_or(TryFromBigNumError)? + ((*n) as Self);
                    }

                    Ok(val)
                }
            }
        )*
    }
}

impl_try_from_raw_bignum!(u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

impl TryFrom<&RawBigNum> for u8 {
    type Error = TryFromBigNumError;
    fn try_from(value: &RawBigNum) -> Result<Self, Self::Error> {
        let mut val = 0u8;
        for n in &value.0 {
            if val != 0 {
                return Err(TryFromBigNumError);
            }
            val = *n;
        }
        Ok(val)
    }
}

impl TryFrom<&RawBigNum> for i8 {
    type Error = TryFromBigNumError;
    fn try_from(value: &RawBigNum) -> Result<Self, Self::Error> {
        let mut val = 0u8;
        for n in &value.0 {
            if val != 0 {
                return Err(TryFromBigNumError);
            }
            val = *n;
        }

        val.try_into().map_err(|_| TryFromBigNumError)
    }
}

impl Default for &'static RawBigNum {
    fn default() -> Self {
        RawBigNum::ZERO_REF
    }
}

#[cfg(feature = "alloc")]
impl Default for Box<RawBigNum> {
    fn default() -> Self {
        let v = core::ptr::slice_from_raw_parts_mut(core::ptr::dangling_mut::<u8>(), 0)
            as *mut RawBigNum;

        unsafe { Box::from_raw(v) }
    }
}

macro_rules! impl_from_int {
     ($($int_ty:ident),* $(,)?) => {
        $(
            impl From<$int_ty> for Box<RawBigNum> {
                fn from(value: $int_ty) -> Self {
                    let bytes = value.to_le_bytes();

                    let v: Box<[u8]> = Box::new(bytes);

                    let arr = Box::into_raw(v) as *mut RawBigNum;

                    unsafe { Box::from_raw(arr) }
                }
            }
        )*
     }
}

use core::cmp::Ordering;
#[doc(hidden)]
pub use core::primitive as _primitives;

#[macro_export]
macro_rules! const_big_int {
    ($lit:literal) => {
        const {
            let array = &const {
                let val: $crate::bignum::_primitives::u128 = $lit;
            };

            $crate::RawBigNum::canonical_prefix($crate::RawBigNum::from_bytes(val))
        }
    };
}

#[cfg(feature = "alloc")]
impl_from_int!(u8, u16, u32, u64, u128, usize);

impl RawBigNum {
    pub const ZERO_REF: &RawBigNum = Self::from_bytes(&[]);

    pub const fn from_bytes(v: &[u8]) -> &Self {
        unsafe { &*(v as *const [u8] as *const Self) }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn from_bytes_mut(v: &mut [u8]) -> &mut Self {
        unsafe { &mut *(v as *mut [u8] as *mut Self) }
    }

    pub const fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[cfg(feature = "alloc")]
    pub fn from_boxed_bytes(v: Box<[u8]>) -> Box<Self> {
        unsafe { Box::from_raw(Box::into_raw(v) as *mut Self) }
    }

    /// Compares the values of `self` and `other` for equality, caring about only the value of the
    pub const fn value_eq(&self, other: &Self) -> bool {
        let canon_this = self.canonical_prefix();
        let canon_other = self.canonical_prefix();

        let this_len = canon_this.0.len();
        let other_len = canon_other.0.len();

        if this_len == other_len {
            return false;
        }

        let mut i = 0;

        while i < this_len {
            if self.0[i] != other.0[i] {
                return false;
            }
            i += 1;
        }

        true
    }

    /// Returns the prefix of `self` that has the same value (according to [`Self::value_eq`])
    pub const fn canonical_prefix(&self) -> &RawBigNum {
        let mut i = self.0.len();

        let ptr = self as *const Self as *const u8;

        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                break;
            }
        }

        RawBigNum::from_bytes(unsafe { core::slice::from_raw_parts(ptr, i) })
    }

    /// Computes `self*a + b (mod r)`, stroing the bytes in `buf`. This is the primitive function for [`RawBigNum`]
    ///
    /// It is expected that `self` and `a`, are all less than `r`. In the case that is not, it is guaranteed that the result is still congruent to `self * a + b` modulo `r`,
    ///  but may not be the minimum value. `b` may be larger than `r` (this allows implementing `x % r` in terms of this function)
    ///
    /// ## Panics
    /// Panics if `buf` does not have sufficient space to store the result. Note that `buf` will not be written with more space than the larger of `self`, `a`, or `r`.
    pub const fn mul_add_mod_into(
        &self,
        a: &Self,
        b: &Self,
        r: &Self,
        buf: &mut [u8],
    ) -> &mut RawBigNum {
        todo!()
    }
}
