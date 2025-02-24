use core::{
    mem::ManuallyDrop,
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use bytemuck::{Pod, Zeroable};
use lc_crypto_primitives::{
    asm::{sbox_lookup, write_bytes_explicit},
    cmp::bytes_eq_secure,
    mem::transmute_unchecked,
};

use crate::traits::SecretTy;

/// `Secret` is a type that wraps a secret value in a manner that only allows opaque operations to be performed on the value, such as conversions to other `Secret` types.
#[repr(transparent)]
pub struct Secret<T: SecretTy + ?Sized>(T);

impl<T: SecretTy + ?Sized> core::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        struct SecretField;

        impl core::fmt::Debug for SecretField {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("_")
            }
        }
        f.debug_tuple("Secret").field(&SecretField).finish()
    }
}

// SAFETY: The impls of `SecretTy` mean that
unsafe impl<T: SecretTy> Zeroable for Secret<T> {}

impl<T: SecretTy> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: SecretTy + Default> Default for Secret<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: SecretTy> Secret<T> {
    pub const fn new(val: T) -> Self {
        Self(val)
    }

    pub const fn as_ptr(&self) -> *const T {
        &raw const self.0
    }

    pub const fn as_mut_ptr(&mut self) -> *mut T {
        &raw mut self.0
    }

    /// Sets the interior secret value to `val`.
    /// This may be faster than `*self = Self::new(val)` because it avoids redundantly zeroing `self`
    pub const fn set(&mut self, val: T) {
        unsafe { core::ptr::write(self, Self::new(val)) }
    }

    pub const fn zeroed() -> Self {
        bytemuck::zeroed()
    }

    pub const fn from_bytes<const N: usize>(val: [u8; N]) -> Self {
        const {
            assert!(N == core::mem::size_of::<T>());
        }

        // Safety: Assured by `T: SecretTy` bound
        Self(unsafe { transmute_unchecked(val) })
    }

    pub const fn must_cast<U: SecretTy>(self) -> Secret<U> {
        const {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<U>());
        }

        unsafe { transmute_unchecked(self) }
    }

    pub const fn must_cast_ref<U: SecretTy>(&self) -> &Secret<U> {
        const {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<U>());
            assert!(core::mem::align_of::<T>() >= core::mem::align_of::<U>());
        }

        unsafe { transmute_unchecked(self) }
    }

    pub const fn must_cast_mut<U: SecretTy>(&mut self) -> &mut Secret<U> {
        const {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<U>());
            assert!(core::mem::align_of::<T>() >= core::mem::align_of::<U>());
        }

        unsafe { transmute_unchecked(self) }
    }

    /// Converts the `secret` value back into a `T`
    ///
    /// Note: This is not an `unsafe` method but may not be what you want. You should use this only at the end of a secret computation,
    ///
    pub const fn into_inner_nonsecret(self) -> T {
        unsafe { transmute_unchecked(self) }
    }
}

impl<T: SecretTy + ?Sized> Secret<T> {
    pub const fn get_nonsecret(&self) -> &T {
        &self.0
    }

    pub const fn get_mut_nonsecret(&mut self) -> &mut T {
        &mut self.0
    }
    pub const fn as_byte_slice(&self) -> &Secret<[u8]> {
        let len = core::mem::size_of_val(self);
        unsafe {
            &*(core::ptr::slice_from_raw_parts((self as *const Self).cast::<u8>(), len) as *const _)
        }
    }

    pub const fn as_byte_slice_mut(&mut self) -> &mut Secret<[u8]> {
        let len = core::mem::size_of_val(self);
        unsafe {
            &mut *(core::ptr::slice_from_raw_parts_mut((self as *mut Self).cast::<u8>(), len)
                as *mut _)
        }
    }

    /// Overwrites `self` with `val`
    /// This is guaranteed (with best-effort cooperation from the compiler) to not be discarded by the optimizer.
    pub fn write_bytes(&mut self, val: u8) {
        let len = core::mem::size_of_val(self);
        let ptr = core::ptr::from_mut(self).cast::<u8>();

        unsafe {
            write_bytes_explicit(ptr, val, len);
        }
    }
}

impl<T: SecretTy> Secret<[T]> {
    pub const fn as_ptr(&self) -> *const T {
        (&raw const self.0).cast()
    }

    pub const fn as_mut_ptr(&mut self) -> *mut T {
        (&raw mut self.0).cast()
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get<I: core::slice::SliceIndex<[T]>>(&self, idx: I) -> Option<&Secret<I::Output>>
    where
        I::Output: SecretTy,
    {
        match self.0.get(idx) {
            Some(out) => Some(unsafe { &*(out as *const _ as *const Secret<_>) }),
            None => None,
        }
    }

    pub fn get_mut<I: core::slice::SliceIndex<[T]>>(
        &mut self,
        idx: I,
    ) -> Option<&mut Secret<I::Output>>
    where
        I::Output: SecretTy,
    {
        match self.0.get_mut(idx) {
            Some(out) => Some(unsafe { &mut *(out as *mut _ as *mut Secret<_>) }),
            None => None,
        }
    }

    pub fn get_unchecked<I: core::slice::SliceIndex<[T]>>(&self, idx: I) -> &Secret<I::Output>
    where
        I::Output: SecretTy,
    {
        unsafe { &*(self.0.get_unchecked(idx) as *const _ as *const Secret<_>) }
    }

    pub fn get_unchecked_mut<I: core::slice::SliceIndex<[T]>>(
        &mut self,
        idx: I,
    ) -> &mut Secret<I::Output>
    where
        I::Output: SecretTy,
    {
        unsafe { &mut *(self.0.get_unchecked_mut(idx) as *mut _ as *mut Secret<_>) }
    }
}

impl<T: SecretTy, I: core::slice::SliceIndex<[T]>> Index<I> for Secret<[T]>
where
    I::Output: SecretTy,
{
    type Output = Secret<I::Output>;
    fn index(&self, index: I) -> &Self::Output {
        unsafe { &*((&self.0[index]) as *const _ as *const Secret<_>) }
    }
}

impl<T: SecretTy, I: core::slice::SliceIndex<[T]>> IndexMut<I> for Secret<[T]>
where
    I::Output: SecretTy,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        unsafe { &mut *((&mut self.0[index]) as *mut _ as *mut Secret<_>) }
    }
}

impl<T: SecretTy + ?Sized> Drop for Secret<T> {
    fn drop(&mut self) {
        self.write_bytes(0);
    }
}

impl<T: SecretTy> Clone for Secret<T> {
    fn clone(&self) -> Self {
        // SAFETY: The def of `SecretTy` means any
        Self(unsafe { core::ptr::read(&self.0) })
    }
}

impl<T: SecretTy + ?Sized> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        core::mem::size_of_val(self) == core::mem::size_of_val(other)
            && bytes_eq_secure(&self.as_byte_slice().0, &other.as_byte_slice().0)
    }
}

impl<T: SecretTy + ?Sized> Eq for Secret<T> {}

#[doc(hidden)]
pub const fn __into_secret<T: SecretTy + ?Sized>(val: *mut T) -> *mut Secret<T> {
    val as *mut Secret<T>
}

#[doc(hidden)]
pub const fn __from_secret<T: SecretTy + ?Sized>(val: *mut Secret<T>) -> *mut T {
    val as *mut T
}

#[macro_export]
macro_rules! project_secret{
    ($base:expr, $($fields:tt).+) => {
        (*$crate::secret::__into_secret(core::ptr::addr_of!((*$crate::secret::__from_secret(core::ptr::addr_of!($base).cast_mut())). $($fields).+).cast_mut()).cast_const())
    }
}

#[macro_export]
macro_rules! project_secret_mut{
    ($base:expr, $($fields:tt).+) => {
        (*$crate::secret::__into_secret(core::ptr::addr_of!((*$crate::secret::__from_secret(core::ptr::addr_of!($base).cast_mut())). $($fields).+).cast_mut()).cast_const())
    }
}

macro_rules! impl_secret_arith{
    ($($ty:ty),*) => {
        $(
            impl core::ops::Add for Secret<$ty> {
                type Output = Self;

                fn add(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_add(other.into_inner_nonsecret()))
                }
            }
            impl core::ops::Add<$ty> for Secret<$ty> {
                type Output = Self;

                fn add(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_add(other))
                }
            }
            impl core::ops::Sub for Secret<$ty> {
                type Output = Self;

                fn sub(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_sub(other.into_inner_nonsecret()))
                }
            }
            impl core::ops::Sub<$ty> for Secret<$ty> {
                type Output = Self;

                fn sub(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_sub(other))
                }
            }
            impl core::ops::Mul for Secret<$ty> {
                type Output = Self;

                fn mul(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_mul(other.into_inner_nonsecret()))
                }
            }
            impl core::ops::Mul<$ty> for Secret<$ty> {
                type Output = Self;

                fn mul(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_mul(other))
                }
            }

            impl core::ops::AddAssign for Secret<$ty> {
                fn add_assign(&mut self, other: Self){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_add(other.into_inner_nonsecret())))}
                }
            }

            impl core::ops::AddAssign<$ty> for Secret<$ty> {
                fn add_assign(&mut self, other: $ty){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_add(other)))}
                }
            }

            impl core::ops::SubAssign for Secret<$ty> {
                fn sub_assign(&mut self, other: Self){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_sub(other.into_inner_nonsecret())))}
                }
            }

            impl core::ops::SubAssign<$ty> for Secret<$ty> {
                fn sub_assign(&mut self, other: $ty){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_sub(other)))}
                }
            }
            impl core::ops::MulAssign for Secret<$ty> {
                fn mul_assign(&mut self, other: Self){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_mul(other.into_inner_nonsecret())))}
                }
            }
            impl core::ops::MulAssign<$ty> for Secret<$ty> {
                fn mul_assign(&mut self, other: $ty){
                    let val = *self.get_nonsecret();

                    unsafe{core::ptr::write(self, Self::new(val.wrapping_mul(other)))}
                }
            }
        )*
    }
}

macro_rules! impl_secret_neg{
    ($($ty:ty),*) => {
        $(
            impl core::ops::Neg for Secret<$ty>{
                type Output = Self;

                fn neg(self) -> Self {
                    Self::new(-self.into_inner_nonsecret())
                }
            }

            impl Secret<$ty>{
                pub const fn negate_in_place(&mut self){
                    unsafe{core::ptr::write(self, Self::new(-*self.get_nonsecret()))}
                }
            }
        )*
    }
}

macro_rules! impl_secret_logic {
    ($($ty:ty),*) => {
        $(
            impl core::ops::BitOr for Secret<$ty> {
                type Output = Self;
                fn bitor(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret() | other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitOr<$ty> for Secret<$ty> {
                type Output = Self;
                fn bitor(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret() | other)
                }
            }

            impl core::ops::BitAnd for Secret<$ty> {
                type Output = Self;
                fn bitand(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret() & other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitAnd<$ty> for Secret<$ty> {
                type Output = Self;
                fn bitand(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret() & other)
                }
            }

            impl core::ops::BitXor for Secret<$ty> {
                type Output = Self;
                fn bitxor(self, other: Self) -> Self {
                    Self::new(self.into_inner_nonsecret() | other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitXor<$ty> for Secret<$ty> {
                type Output = Self;
                fn bitxor(self, other: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret() ^ other)
                }
            }

            impl core::ops::Not for Secret<$ty> {
                type Output = Self;

                fn not(self) -> Self{
                    Self::new(!self.into_inner_nonsecret())
                }
            }

            impl Secret<$ty>{
                pub const fn not_in_place(&mut self){
                    let val = *self.get_nonsecret();
                    self.set(!val)
                }
            }

            impl core::ops::BitOrAssign for Secret<$ty> {
                fn bitor_assign(&mut self, other: Self) {
                    let val = *self.get_nonsecret();
                    self.set(val | other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitOrAssign<$ty> for Secret<$ty> {
                fn bitor_assign(&mut self, other: $ty) {
                    let val = *self.get_nonsecret();
                    self.set(val | other)
                }
            }

            impl core::ops::BitAndAssign for Secret<$ty> {
                fn bitand_assign(&mut self, other: Self) {
                    let val = *self.get_nonsecret();
                    self.set(val & other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitAndAssign<$ty> for Secret<$ty> {
                fn bitand_assign(&mut self, other: $ty) {
                    let val = *self.get_nonsecret();
                    self.set(val & other)
                }
            }

            impl core::ops::BitXorAssign for Secret<$ty> {
                fn bitxor_assign(&mut self, other: Self) {
                    let val = *self.get_nonsecret();
                    self.set(val ^ other.into_inner_nonsecret())
                }
            }
            impl core::ops::BitXorAssign<$ty> for Secret<$ty> {
                fn bitxor_assign(&mut self, other: $ty) {
                    let val = *self.get_nonsecret();
                    self.set(val ^ other)
                }
            }
        )*
    }
}

impl_secret_arith! {u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize}

impl_secret_neg! {i8, i16, i32, i64, i128, isize}

impl_secret_logic! {
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
}

impl Secret<[u8; 256]> {
    pub fn sbox_lookup(&self, key: &Secret<u8>) -> Secret<u8> {
        // SAFETY:
        // self.as_ptr() is guaranteed dereferenceable by `&self`
        Secret::new(unsafe { sbox_lookup(*key.get_nonsecret(), self.as_ptr()) })
    }
}
