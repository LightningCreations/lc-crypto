use core::{
    alloc::Layout,
    iter::FusedIterator,
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use bytemuck::{Pod, Zeroable};
use lc_crypto_primitives::{
    asm::{sbox_lookup, write_bytes_explicit},
    cmp::bytes_eq_secure,
    mem::transmute_unchecked,
    traits::ByteArray,
};

use lc_crypto_primitives::traits::{SealedSecret, SecretTy};

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
/// Note that [`Div`][core::ops::Div] and [`Rem`][core::ops::Rem] are not implemented intentional.
///
/// [`core::fmt::Debug`] allows printing [`Secret`], but will not print the interior value (Instead it prints an opaque string).
/// There is no [`core::fmt::Display`] (or other trait) implementations.
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

// SAFETY: The impls of `SecretTy` mean that `T: Pod``
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
    ///
    /// Sattically fails to compile if `val` is not the same size as `T`
    pub const fn from_bytes<const N: usize>(val: [u8; N]) -> Self {
        const {
            assert!(N == core::mem::size_of::<T>());
        }

        // Safety: Assured by `T: SecretTy` bound
        Self(unsafe { transmute_unchecked(val) })
    }

    /// Safely transmutes to [`Secret<U>`] (validated by [`Pod`]).
    ///
    /// Fails to compile if `T` and `U` are different sizes
    pub const fn must_cast<U: SecretTy>(self) -> Secret<U> {
        const {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<U>());
        }

        unsafe { transmute_unchecked(self) }
    }

    /// Safely does a pointer-cast to [`Secret<U>`] (validated by [`Pod`]).
    ///
    /// Fails to compile if `T` and `U` are different sizes or `U` is more strictly aligned than `U`
    pub const fn must_cast_ref<U: SecretTy>(&self) -> &Secret<U> {
        const {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<U>());
            assert!(core::mem::align_of::<T>() >= core::mem::align_of::<U>());
        }

        unsafe { transmute_unchecked(self) }
    }

    /// Safely does a pointer-cast to [`Secret<U>`] (validated by [`Pod`]).
    ///
    /// Fails to compile if `T` and `U` are different sizes or `U` is more strictly aligned than `U`
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
    /// Creates a [`Secret`] wrapper for an existing `&T`.
    pub const fn from_ref(x: &T) -> &Self {
        unsafe { &*(x as *const T as *const Self) }
    }

    /// Creates a [`Secret`] wrapper for an existing `&mut T`
    pub const fn from_mut(x: &mut T) -> &mut Self {
        unsafe { &mut *(x as *mut T as *mut Self) }
    }

    /// Gets the inner value, bypassing [`Secret`].
    ///
    /// Note: This is not an `unsafe` method but may not be what you want. You should use this only at the end of a secret computation.
    ///
    /// If you are using this to project into a [`Secret`], use [`project_secret!`][crate::project_secret] instead (which returns a [`Secret<T>`] place)
    pub const fn get_nonsecret(&self) -> &T {
        &self.0
    }

    /// Gets the inner value, bypassing [`Secret`].
    ///
    /// Note: This is not an `unsafe` method but may not be what you want. You should use this only at the end of a secret computation.
    ///
    /// If you are using this to project into a [`Secret`], use [`project_secret_mut!`[crate::project_secret_mut] instead (which returns a [`Secret<T>`] place)
    pub const fn get_mut_nonsecret(&mut self) -> &mut T {
        &mut self.0
    }

    /// Obtains a `[u8]` slice to the inner value.
    pub const fn as_byte_slice(&self) -> &Secret<[u8]> {
        let len = core::mem::size_of_val(self);
        unsafe {
            &*(core::ptr::slice_from_raw_parts((self as *const Self).cast::<u8>(), len) as *const _)
        }
    }

    /// Obtains a `[u8]` slice to the inner value.
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
    /// Gets a raw pointer to the start of slice
    /// This is equivalent to [`Secret<T>::as_ptr`], but returns the raw pointer from the slice itself
    pub const fn as_ptr(&self) -> *const T {
        (&raw const self.0).cast()
    }

    /// Gets a raw pointer to the start of slice
    /// This is equivalent to [`Secret<T>::as_ptr`], but returns the raw pointer from the slice itself
    pub const fn as_mut_ptr(&mut self) -> *mut T {
        (&raw mut self.0).cast()
    }

    /// Computes the length of the slice.
    ///
    /// Note that the length of a [`Secret`] slice is not generally deemed secret, and therefore it is not wrapped in [`Secret`].
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Optionally indexes into `self` using [`SliceIndex`], wrapping the result in a [`Secret`]
    ///
    /// Returns [`None`] if `idx` is out of bounds of `self`
    /// # Notes
    /// Due to type system limitations, this can't be used generically without adding an `I::Output: SecretTy` bound.
    pub fn get<I: SliceIndex<[T]>>(&self, idx: I) -> Option<&Secret<I::Output>>
    where
        I::Output: SecretTy,
    {
        match self.0.get(idx) {
            Some(out) => Some(unsafe { &*(out as *const _ as *const Secret<_>) }),
            None => None,
        }
    }

    /// Optionally indexes into `self` mutably using [`SliceIndex`], wrapping the result in a [`Secret`]
    ///
    /// Returns [`None`] if `idx` is out of bounds of `self`
    /// # Notes
    /// Due to type system limitations, this can't be used generically without adding an `I::Output: SecretTy` bound.
    pub fn get_mut<I: SliceIndex<[T]>>(&mut self, idx: I) -> Option<&mut Secret<I::Output>>
    where
        I::Output: SecretTy,
    {
        match self.0.get_mut(idx) {
            Some(out) => Some(unsafe { &mut *(out as *mut _ as *mut Secret<_>) }),
            None => None,
        }
    }

    /// Performs an unchecked indexing into `self`, wrapping the result in a [`Secret`]
    ///
    /// # Safety
    ///
    /// `idx` must be inbounds of `self`, even if the result is never used
    /// # Notes
    /// Due to type system limitations, this can't be used generically without adding an `I::Output: SecretTy` bound.
    pub fn get_unchecked<I: SliceIndex<[T]>>(&self, idx: I) -> &Secret<I::Output>
    where
        I::Output: SecretTy,
    {
        unsafe { &*(self.0.get_unchecked(idx) as *const _ as *const Secret<_>) }
    }

    /// Performs an unchecked mutable indexing into `self`.
    ///
    /// # Safety
    ///
    /// `idx` must be inbounds of `self`, even if the result is never used
    /// # Notes
    /// Due to type system limitations, this can't be used generically without adding an `I::Output: SecretTy` bound.
    pub fn get_unchecked_mut<I: SliceIndex<[T]>>(&mut self, idx: I) -> &mut Secret<I::Output>
    where
        I::Output: SecretTy,
    {
        unsafe { &mut *(self.0.get_unchecked_mut(idx) as *mut _ as *mut Secret<_>) }
    }
}

impl<T: SecretTy, I: SliceIndex<[T]>> Index<I> for Secret<[T]>
where
    I::Output: SecretTy,
{
    type Output = Secret<I::Output>;
    fn index(&self, index: I) -> &Self::Output {
        unsafe { &*((&self.0[index]) as *const _ as *const Secret<_>) }
    }
}

impl<T: SecretTy, I: SliceIndex<[T]>> IndexMut<I> for Secret<[T]>
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

    fn clone_from(&mut self, source: &Self) {
        self.set(unsafe { core::ptr::read(&source.0) })
    }
}

#[cfg(feature = "alloc")]
impl<T: SecretTy> alloc::borrow::ToOwned for Secret<[T]> {
    type Owned = alloc::boxed::Box<Self>;

    fn to_owned(&self) -> alloc::boxed::Box<Self> {
        self.into()
    }
}

#[cfg(all(feature = "alloc", not(feature = "nightly-allocator_api")))]
#[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
impl<T: SecretTy + ?Sized> From<&Secret<T>> for alloc::boxed::Box<Secret<T>> {
    fn from(value: &Secret<T>) -> Self {
        let layout = Layout::for_value(value);

        let metadata = <T as Sealed>::into_raw_parts(core::ptr::addr_of!(value.0).cast_mut()).1;

        let ptr: *mut () = if layout.size() == 0 {
            core::ptr::without_provenance_mut(layout.align())
        } else {
            unsafe { alloc::alloc::alloc(layout) }.cast()
        };

        if !ptr.is_null() {
            let ptr = <T as Sealed>::from_raw_parts(ptr, metadata);

            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::addr_of!(value.0).cast::<u8>(),
                    ptr.cast::<u8>(),
                    layout.size(),
                );
            }

            unsafe { alloc::boxed::Box::from_raw(ptr as *mut Secret<T>) }
        } else {
            alloc::alloc::handle_alloc_error(layout)
        }
    }
}
#[cfg(all(feature = "alloc", feature = "nightly-allocator_api"))]
#[cfg_attr(
    feature = "nightly-docs",
    doc(cfg(all(feature = "alloc", feature = "nightly-allocator_api")))
)]
impl<T: SecretTy + ?Sized, A: alloc::alloc::Allocator + Default> From<&Secret<T>>
    for alloc::boxed::Box<Secret<T>, A>
{
    fn from(value: &Secret<T>) -> Self {
        let layout = Layout::for_value(value);

        let metadata =
            <T as SealedSecret>::into_raw_parts(core::ptr::addr_of!(value.0).cast_mut()).1;

        let alloc = A::default();

        if let Ok(ptr) = alloc.allocate(layout) {
            let ptr = ptr.as_ptr().cast::<()>();

            let ptr = <T as SealedSecret>::from_raw_parts(ptr, metadata);

            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::addr_of!(value.0).cast::<u8>(),
                    ptr.cast::<u8>(),
                    layout.size(),
                );
            }

            unsafe { alloc::boxed::Box::from_raw_in(ptr as *mut Secret<T>, alloc) }
        } else {
            alloc::alloc::handle_alloc_error(layout)
        }
    }
}

impl<T: SecretTy + ?Sized> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        core::mem::size_of_val(self) == core::mem::size_of_val(other)
            && bytes_eq_secure(&self.as_byte_slice().0, &other.as_byte_slice().0)
    }
}

impl<T: SecretTy + ?Sized> Eq for Secret<T> {}

impl Secret<[u8]> {
    pub fn array_chunks<A: ByteArray>(&self) -> ArrayChunks<'_, A> {
        ArrayChunks(A::array_chunks(self.get_nonsecret()))
    }
}

pub struct ArrayChunks<'a, A: 'static>(lc_crypto_primitives::traits::ArrayChunks<'a, A>);

impl<'a, A: ByteArray> ArrayChunks<'a, A> {
    pub fn remainder(&self) -> &'a Secret<[u8]> {
        Secret::from_ref(self.0.remainder())
    }
}

impl<'a, A: ByteArray> Iterator for ArrayChunks<'a, A> {
    type Item = &'a Secret<A>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Secret::from_ref)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a, A: ByteArray> ExactSizeIterator for ArrayChunks<'a, A> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a, A: ByteArray> DoubleEndedIterator for ArrayChunks<'a, A> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(Secret::from_ref)
    }
}

impl<'a, A: ByteArray> FusedIterator for ArrayChunks<'a, A> {}

#[cfg(feature = "alloc")]
impl<T: SecretTy> Secret<T> {
    /// Creates a [`Box`] containing a zereod `T`
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
    pub fn box_zeroed() -> alloc::boxed::Box<Self> {
        let layout = Layout::new::<T>();

        let ptr: *mut T = if layout.size() == 0 {
            core::ptr::dangling_mut()
        } else {
            unsafe { alloc::alloc::alloc_zeroed(layout).cast() }
        };

        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout)
        }

        unsafe { Box::from_raw(ptr as *mut Self) }
    }

    /// Creates a [`Box`] containing a zeroed `T` in `alloc`
    #[cfg_attr(
        feature = "nightly-docs",
        doc(cfg(all(feature = "alloc", feature = "nightly-allocator_api")))
    )]
    #[cfg(feature = "nightly-allocator_api")]
    pub fn box_zeroed_in<A: alloc::alloc::Allocator>(alloc: A) -> alloc::boxed::Box<Self, A> {
        let layout = Layout::new::<T>();

        let Ok(ptr) = alloc.allocate(layout) else {
            alloc::alloc::handle_alloc_error(layout)
        };

        unsafe { Box::from_raw_in(ptr.as_ptr().cast::<T>() as *mut Self, alloc) }
    }
}

impl<S: SecretTy + ?Sized> AsRef<Secret<[u8]>> for Secret<S> {
    fn as_ref(&self) -> &Secret<[u8]> {
        self.as_byte_slice()
    }
}

impl<S: SecretTy + ?Sized> AsMut<Secret<[u8]>> for Secret<S> {
    fn as_mut(&mut self) -> &mut Secret<[u8]> {
        self.as_byte_slice_mut()
    }
}

impl AsRef<Secret<[u8]>> for [u8] {
    fn as_ref(&self) -> &Secret<[u8]> {
        Secret::from_ref(self)
    }
}

impl AsMut<Secret<[u8]>> for [u8] {
    fn as_mut(&mut self) -> &mut Secret<[u8]> {
        Secret::from_mut(self)
    }
}

impl<const N: usize> AsRef<Secret<[u8]>> for [u8; N] {
    fn as_ref(&self) -> &Secret<[u8]> {
        Secret::from_ref(self)
    }
}

impl<const N: usize> AsMut<Secret<[u8]>> for [u8; N] {
    fn as_mut(&mut self) -> &mut Secret<[u8]> {
        Secret::from_mut(self)
    }
}

impl AsRef<Secret<[u8]>> for str {
    fn as_ref(&self) -> &Secret<[u8]> {
        Secret::from_ref(self.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl<T: SecretTy> Secret<[T]> {
    /// Creates a [`Box`] containing `elems` zeroed values of type `T`
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "alloc")))]
    pub fn box_zeroed_slice(elems: usize) -> alloc::boxed::Box<Self> {
        let Ok(layout) = Layout::array::<T>(elems) else {
            panic!("{elems} exceeded `isize` bounds")
        };

        let ptr: *mut T = if layout.size() == 0 {
            core::ptr::dangling_mut()
        } else {
            unsafe { alloc::alloc::alloc_zeroed(layout).cast() }
        };

        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout)
        }

        unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, elems) as *mut Self) }
    }

    /// Creates a [`Box`] containing `elems` zeroed values of type `T` in `alloc`
    #[cfg_attr(
        feature = "nightly-docs",
        doc(cfg(all(feature = "alloc", feature = "nightly-allocator_api")))
    )]
    pub fn box_zeroed_slice_in<A: alloc::alloc::Allocator>(
        elems: usize,
        alloc: A,
    ) -> alloc::boxed::Box<Self, A> {
        let Ok(layout) = Layout::array::<T>(elems) else {
            panic!("{elems} exceeded `isize` bounds")
        };

        let Ok(ptr) = alloc.allocate(layout) else {
            alloc::alloc::handle_alloc_error(layout)
        };

        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.as_ptr().cast::<T>(), elems) as *mut Self,
                alloc,
            )
        }
    }
}

#[cfg(feature = "std")]

impl<T: SecretTy> Secret<T> {
    /// Reads a [`Secret<T>`] from an input stream.
    /// Fails unless it can read the whole value.
    ///
    /// Note that there is no `write` counterpart. Instead, you must call [`Secret::get_nonsecret`] to get the inner value, then write that to demonstrate that the value is no longer deemed secret.
    #[cfg_attr(feature = "nightly-docs", doc(cfg(feature = "std")))]
    pub fn read<R: std::io::Read>(mut read: R) -> std::io::Result<Self> {
        let mut this = Self::zeroed();

        let bytes = &mut this.as_byte_slice_mut().0;

        read.read_exact(bytes)?;

        Ok(this)
    }
}

#[doc(hidden)]
pub const fn __into_secret<T: SecretTy + ?Sized>(x: &T) -> &Secret<T> {
    unsafe { core::mem::transmute(x) }
}

#[doc(hidden)]
pub const fn __into_secret_mut<T: SecretTy + ?Sized>(x: &mut T) -> &mut Secret<T> {
    unsafe { core::mem::transmute(x) }
}

/// Projects a field of a [`Secret`] immutable place.
///
/// The resulting expression is an immutable place expression, with the following characteristics:
/// * If `$base` has type [`Secret<T>`], and `$($fields).+` are (potentially nested) fields of type `T`, with a type of `U`, then the type is [`Secret<U>`],
/// * The address of the place is
///
/// Due to limitations in `Rust`, this cannot project to a field of a `#[repr(packed)]` type.
///
/// It also cannot project to a field that has a type which is not a [`SecretTy`]
#[macro_export]
macro_rules! project_secret{
    ($base:expr, $($fields:tt).+) => {
        (*$crate::secret::__into_secret(&$crate::secret::Secret::get_nonsecret(&$base). ($fields).+))
    }
}

/// Projects a field of a [`Secret`] mutable place.
///
/// The resulting expression is an mutable place expression, with the following characteristics:
/// * If `$base` has type [`Secret<T>`], and `$($fields).+` are (potentially nested) fields of type `T`, with a type of `U`, then the type is [`Secret<U>`],
/// * The address of the place is
///
/// Due to limitations in `Rust`, this cannot project to a field of a `#[repr(packed)]` type.
///
/// It also cannot project to a field that has a type which is not a [`SecretTy`]
#[macro_export]
macro_rules! project_secret_mut{
    ($base:expr, $($fields:tt).+) => {
        (*$crate::secret::__into_secret_mut(&mut $crate::secret::Secret::get_mut_nonsecret(&mut $base). ($fields).+))
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

            /// Negates the secret value in place
            ///
            /// This is equivalent to `self.set(-self.clone())`
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
                /// Inverts the secret value in place
                ///
                /// This is equivalent to `self.set(!self.clone())`
                pub const fn not_in_place(&mut self){
                    let val = *self.get_nonsecret();
                    self.set(!val)
                }
            }
        )*
    }
}

macro_rules! impl_secret_shift {
    ($($ty:ty),*) => {
        $(
            impl core::ops::Shl<u32> for Secret<$ty> {
                type Output = Self;

                fn shl(self, val: u32) -> Self {
                    Self::new(self.into_inner_nonsecret() << val)
                }
            }
            impl core::ops::Shr<u32> for Secret<$ty> {
                type Output = Self;

                fn shr(self, val: u32) -> Self {
                    Self::new(self.into_inner_nonsecret() >> val )
                }
            }
            impl core::ops::ShlAssign<u32> for Secret<$ty> {
                fn shl_assign(&mut self, val: u32){
                    let r = *self.get_nonsecret();

                    self.set(r << val)
                }
            }
            impl core::ops::ShrAssign<u32> for Secret<$ty> {
                fn shr_assign(&mut self, val: u32) {
                    let r = *self.get_nonsecret();

                    self.set(r >> val)
                }
            }

            impl Secret<$ty> {
                /// Rotate `self` left `bits` bits.
                #[inline(always)]
                pub const fn rotate_left(self, bits: u32) -> Self{
                    Self::new(self.into_inner_nonsecret().rotate_left(bits))
                }

                /// Rotate `self` right `bits` bits.
                #[inline(always)]
                pub const fn rotate_right(self, bits: u32) -> Self{
                    Self::new(self.into_inner_nonsecret().rotate_right(bits))
                }
            }
        )*
    }
}

macro_rules! impl_secret_shift_self {
    ($($ty:ty),*) => {
        $(
            impl core::ops::Shl<$ty> for Secret<$ty> {
                type Output = Self;

                fn shl(self, val: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret() << val)
                }
            }
            impl core::ops::Shr<$ty> for Secret<$ty> {
                type Output = Self;

                fn shr(self, val: $ty) -> Self {
                    Self::new(self.into_inner_nonsecret() << val )
                }
            }

            impl core::ops::ShlAssign<$ty> for Secret<$ty> {
                fn shl_assign(&mut self, val: $ty) {
                    let r = *self.get_nonsecret();

                    self.set(r << val)
                }
            }
            impl core::ops::ShrAssign<$ty> for Secret<$ty> {
                fn shr_assign(&mut self, val: $ty){
                    let r = *self.get_nonsecret();

                    self.set(r >> val)
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

impl_secret_shift! {u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize}
impl_secret_shift_self! {u8, u16, u64, u128, usize, i8, i16, i32, i64, i128, isize}

impl Secret<u8> {
    /// Looks up `self`in a substituion box given by a non-secret array.
    /// This performs an operation that is defensive against side-channels created by both compiler optimizations and cache ops
    pub fn sbox_lookup(&self, sbox: &[u8; 256]) -> Secret<u8> {
        // SAFETY:
        // `sbox` is guaranteed dereferenceable
        Secret::new(unsafe { sbox_lookup(*self.get_nonsecret(), core::ptr::from_ref(sbox)) })
    }

    /// Same as [`Secret::sbox_lookup`] but allows an sbox computed from a secret input.
    pub fn sbox_lookup_secret(&self, secret_sbox: &Secret<[u8; 256]>) -> Secret<u8> {
        // SAFETY:
        // `sbox` is guaranteed dereferenceable
        Secret::new(unsafe { sbox_lookup(*self.get_nonsecret(), secret_sbox.as_ptr()) })
    }
}
