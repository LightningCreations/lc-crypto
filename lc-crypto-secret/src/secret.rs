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

/// [`Secret<T>`] is a type that wraps a secret value in a manner that only allows opaque operations to be performed on the value, such as conversions to other `Secret` types.
///
/// `T` must be a secret type (implement the [`SecretTy`]) trait, which are types that implement [`Pod`] and [`Eq`] (and slices of such types).
///
/// [`Secret`] will be zeroed on drop, though this is only best effort as copies may be made by the compiler freely.
///
/// [`Secret`] is `repr(transparent)` over its element. Note that transmuting to the element type removes the secret protection.
///
/// # Trait Implementations
///
/// [`Zeroable`] is unconditionally implemented (Which is correct because [`SecretTy`] proves that `T` is [`Pod`] and thus [`Zeroable`]).
///
/// [`PartialEq`] and [`Eq`] are implemented. [`PartialEq<T>`] is also implemented.
/// These perform a bytewise comparison (rather than a valuewise comparison), using [`bytes_eq_secure`] to avoid side-channels being created by a non-opaque comparison.
///
/// [`Clone`] is implemented and does a trivial of the underlying value (due to drop only zeroing the contents of the value securely).
/// [`Copy`] is not implemented due to the [`Drop`] impl.
///
/// Many [`core::ops`] are implemented for [`Secret<T>`] when `T` is a primitive type.
/// [`Index`] and [`IndexMut`] are available for slices and return references to [`Secret`] values within the slice.
///
/// Arithmetic operations (like [`Add`][core::ops::Add]) use wrapping arithmetic (unless `T` is wrapped in [`core::num::Saturating`], in which case Saturating arithmetic is used) and do not panic on overflow.
/// Note that [`Div`][core::ops::Div] and [`Rem`][core::ops::Rem] are not implemented
///
/// [`core::fmt::Debug`] allows printing [`Secret`], but will not print the interior value (Instead it prints an opaque string).
/// There is no [`core::fmt::Display`] (or other trait)
///
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
    /// Creates a new secret value that stores `val`.
    /// This is an entry point for creating secret values
    pub const fn new(val: T) -> Self {
        Self(val)
    }

    /// Gets a raw pointer to the inner value.
    ///
    /// # Safety
    /// The returned pointer can be dereferenced for the lifetime of `self`. It must only be used to reading (not writing to) `self`.
    /// Taking a mutable reference to the [`Secret`] or assigning to it invalidates the returned pointer
    pub const fn as_ptr(&self) -> *const T {
        &raw const self.0
    }

    /// Gets a mutable raw pointer to the inner value.
    ///
    /// # Safety
    /// The returned pointer can be dereferenced for the lifetime of `self`.
    /// Using `self` in any way (other than via the return value) invalidates the pointer
    pub const fn as_mut_ptr(&mut self) -> *mut T {
        &raw mut self.0
    }

    /// Sets the interior secret value to `val`.
    /// This may be faster than `*self = Self::new(val)` because it avoids redundantly zeroing `self` first
    pub const fn set(&mut self, val: T) {
        unsafe { core::ptr::write(self, Self::new(val)) }
    }

    /// Creates a Secret value set to all zeroes.
    /// This is equivalent to calling [`bytemuck::zeroed()`] or (a safe version of) [`core::mem::zeroed()`].
    pub const fn zeroed() -> Self {
        bytemuck::zeroed()
    }

    /// Constructs a Secret Value from a a byte array.
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

macro_rules! impl_binary_trait {
    ($prim_ty:ty,  $tr_name:ident, $assign_tr_name:ident, $op_method:ident, $assign_op_method:ident, $wrapping_op:ident, $saturating_op:ident) => {
        const _: () = {
            #[allow(unused_imports)] // Used by `impl_secret_logic`
            use core::ops::$tr_name;
            impl core::ops::$tr_name for Secret<$prim_ty> {
                type Output = Self;

                fn $op_method(self, other: Self) -> Self {
                    Self::new(
                        self.into_inner_nonsecret()
                            .$wrapping_op(other.into_inner_nonsecret()),
                    )
                }
            }
            impl core::ops::$tr_name<$prim_ty> for Secret<$prim_ty> {
                type Output = Self;

                fn $op_method(self, other: $prim_ty) -> Self {
                    Self::new(self.into_inner_nonsecret().$wrapping_op(other))
                }
            }

            impl core::ops::$tr_name<&$prim_ty> for Secret<$prim_ty> {
                type Output = Self;

                fn $op_method(self, other: &$prim_ty) -> Self {
                    Self::new(self.into_inner_nonsecret().$wrapping_op(*other))
                }
            }

            impl core::ops::$tr_name<&Self> for Secret<$prim_ty> {
                type Output = Self;

                fn $op_method(self, other: &Self) -> Self {
                    Self::new(
                        self.into_inner_nonsecret()
                            .$wrapping_op(*other.get_nonsecret()),
                    )
                }
            }

            impl core::ops::$assign_tr_name for Secret<$prim_ty> {
                fn $assign_op_method(&mut self, other: Self) {
                    let __val = *self.get_nonsecret();
                    self.set(__val.$wrapping_op(other.into_inner_nonsecret()))
                }
            }

            impl core::ops::$assign_tr_name<$prim_ty> for Secret<$prim_ty> {
                fn $assign_op_method(&mut self, other: $prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(__val.$wrapping_op(other))
                }
            }

            impl core::ops::$assign_tr_name<&Self> for Secret<$prim_ty> {
                fn $assign_op_method(&mut self, other: &Self) {
                    let __val = *self.get_nonsecret();
                    self.set(__val.$wrapping_op(*other.get_nonsecret()))
                }
            }

            impl core::ops::$assign_tr_name<&$prim_ty> for Secret<$prim_ty> {
                fn $assign_op_method(&mut self, other: &$prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(__val.$wrapping_op(*other))
                }
            }

            // Explicit Wrapping support

            impl core::ops::$tr_name for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: Self) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret()
                            .0
                            .$wrapping_op(other.into_inner_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$tr_name<Secret<$prim_ty>> for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: Secret<$prim_ty>) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret()
                            .0
                            .$wrapping_op(other.into_inner_nonsecret()),
                    ))
                }
            }

            impl core::ops::$tr_name<$prim_ty> for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: $prim_ty) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret().0.$wrapping_op(other),
                    ))
                }
            }

            impl core::ops::$tr_name<&$prim_ty> for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &$prim_ty) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret().0.$wrapping_op(*other),
                    ))
                }
            }

            impl core::ops::$tr_name<&Self> for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &Self) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret()
                            .0
                            .$wrapping_op(other.get_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$tr_name<&Secret<$prim_ty>> for Secret<core::num::Wrapping<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &Secret<$prim_ty>) -> Self {
                    Self::new(core::num::Wrapping(
                        self.into_inner_nonsecret()
                            .0
                            .$wrapping_op(*other.get_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name for Secret<core::num::Wrapping<$prim_ty>> {
                fn $assign_op_method(&mut self, other: Self) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(
                        __val.0.$wrapping_op(other.into_inner_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<Secret<$prim_ty>>
                for Secret<core::num::Wrapping<$prim_ty>>
            {
                fn $assign_op_method(&mut self, other: Secret<$prim_ty>) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(
                        __val.0.$wrapping_op(other.into_inner_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<$prim_ty> for Secret<core::num::Wrapping<$prim_ty>> {
                fn $assign_op_method(&mut self, other: $prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(__val.0.$wrapping_op(other)))
                }
            }

            impl core::ops::$assign_tr_name<&Self> for Secret<core::num::Wrapping<$prim_ty>> {
                fn $assign_op_method(&mut self, other: &Self) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(
                        __val.0.$wrapping_op(other.get_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<&Secret<$prim_ty>>
                for Secret<core::num::Wrapping<$prim_ty>>
            {
                fn $assign_op_method(&mut self, other: &Secret<$prim_ty>) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(
                        __val.0.$wrapping_op(*other.get_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<&$prim_ty> for Secret<core::num::Wrapping<$prim_ty>> {
                fn $assign_op_method(&mut self, other: &$prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Wrapping(__val.0.$wrapping_op(*other)))
                }
            }

            // Explicit Saturation support

            impl core::ops::$tr_name for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: Self) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret()
                            .0
                            .$saturating_op(other.into_inner_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$tr_name<Secret<$prim_ty>> for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: Secret<$prim_ty>) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret()
                            .0
                            .$saturating_op(other.into_inner_nonsecret()),
                    ))
                }
            }

            impl core::ops::$tr_name<$prim_ty> for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: $prim_ty) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret().0.$saturating_op(other),
                    ))
                }
            }

            impl core::ops::$tr_name<&$prim_ty> for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &$prim_ty) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret().0.$saturating_op(*other),
                    ))
                }
            }

            impl core::ops::$tr_name<&Self> for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &Self) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret()
                            .0
                            .$saturating_op(other.get_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$tr_name<&Secret<$prim_ty>> for Secret<core::num::Saturating<$prim_ty>> {
                type Output = Self;

                fn $op_method(self, other: &Secret<$prim_ty>) -> Self {
                    Self::new(core::num::Saturating(
                        self.into_inner_nonsecret()
                            .0
                            .$saturating_op(*other.get_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name for Secret<core::num::Saturating<$prim_ty>> {
                fn $assign_op_method(&mut self, other: Self) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(
                        __val.0.$saturating_op(other.into_inner_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<Secret<$prim_ty>>
                for Secret<core::num::Saturating<$prim_ty>>
            {
                fn $assign_op_method(&mut self, other: Secret<$prim_ty>) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(
                        __val.0.$saturating_op(other.into_inner_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<$prim_ty> for Secret<core::num::Saturating<$prim_ty>> {
                fn $assign_op_method(&mut self, other: $prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(__val.0.$saturating_op(other)))
                }
            }

            impl core::ops::$assign_tr_name<&Self> for Secret<core::num::Saturating<$prim_ty>> {
                fn $assign_op_method(&mut self, other: &Self) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(
                        __val.0.$saturating_op(other.get_nonsecret().0),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<&Secret<$prim_ty>>
                for Secret<core::num::Saturating<$prim_ty>>
            {
                fn $assign_op_method(&mut self, other: &Secret<$prim_ty>) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(
                        __val.0.$saturating_op(*other.get_nonsecret()),
                    ))
                }
            }

            impl core::ops::$assign_tr_name<&$prim_ty> for Secret<core::num::Saturating<$prim_ty>> {
                fn $assign_op_method(&mut self, other: &$prim_ty) {
                    let __val = *self.get_nonsecret();
                    self.set(core::num::Saturating(__val.0.$saturating_op(*other)))
                }
            }
        };
    };
}

macro_rules! impl_secret_arith{
    ($($ty:ty),*) => {
        $(
            impl_binary_trait!($ty, Add, AddAssign, add, add_assign, wrapping_add, saturating_add);
            impl_binary_trait!($ty, Sub, SubAssign, sub, sub_assign, wrapping_sub, saturating_sub);
            impl_binary_trait!($ty, Mul, MulAssign, mul, mul_assign, wrapping_mul, saturating_mul);
        )*
    }
}

macro_rules! impl_secret_neg{
    ($($ty:ty),*) => {
        $(
            impl core::ops::Neg for Secret<$ty>{
                type Output = Self;

                fn neg(self) -> Self {
                    Self::new(self.into_inner_nonsecret().wrapping_neg())
                }
            }

            impl Secret<$ty>{
                pub const fn negate_in_place(&mut self){
                    unsafe{core::ptr::write(self, Self::new((*self.get_nonsecret()).wrapping_neg()))}
                }
            }
        )*
    }
}

macro_rules! impl_secret_logic {
    ($($ty:ty),*) => {
        $(
            impl_binary_trait!($ty, BitAnd, BitAndAssign, bitand, bitand_assign, bitand, bitand);
            impl_binary_trait!($ty, BitOr, BitOrAssign, bitor, bitor_assign, bitor, bitor);
            impl_binary_trait!($ty, BitXor, BitXorAssign, bitxor, bitxor_assign, bitxor, bitxor);

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
        )*
    }
}

impl_secret_arith! {u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize}

impl_secret_neg! {i8, i16, i32, i64, i128, isize}

impl_secret_logic! {
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
}

impl Secret<u8> {
    /// Looks up `self`in a substituion box given by a non-secret array.
    /// This performs an operation that is defensive against side-channels created by both compiler optimizations and cache ops
    pub fn sbox_lookup(&self, sbox: &[u8; 256]) -> Secret<u8> {
        // SAFETY:
        // `sbox` is guaranteed dereferenceable
        Secret::new(unsafe { sbox_lookup(*self.get_nonsecret(), core::ptr::from_ref(sbox)) })
    }

    pub fn sbox_lookup_secret(&self, secret_sbox: &Secret<[u8; 256]>) -> Secret<u8> {
        // SAFETY:
        // `sbox` is guaranteed dereferenceable
        Secret::new(unsafe { sbox_lookup(*self.get_nonsecret(), secret_sbox.as_ptr()) })
    }
}
