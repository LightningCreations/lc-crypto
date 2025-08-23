mod private {
    use core::iter::FusedIterator;

    pub trait Sealed {}

    pub struct ArrayChunks<'a, T: 'a, const N: usize>(
        pub(crate) core::slice::ArrayChunks<'a, T, N>,
    );

    impl<'a, T: 'a, const N: usize> Iterator for ArrayChunks<'a, T, N> {
        type Item = &'a [T; N];

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            self.0.size_hint()
        }

        fn nth(&mut self, n: usize) -> Option<Self::Item> {
            self.0.nth(n)
        }
    }

    impl<'a, T: 'a, const N: usize> DoubleEndedIterator for ArrayChunks<'a, T, N> {
        fn next_back(&mut self) -> Option<Self::Item> {
            self.0.next_back()
        }
    }

    impl<'a, T: 'a, const N: usize> ExactSizeIterator for ArrayChunks<'a, T, N> {
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    impl<'a, T: 'a, const N: usize> FusedIterator for ArrayChunks<'a, T, N> {}

    pub trait SealedSecret {
        type Metadata: Sized + Copy + Eq;
        fn foo(&self) -> &Self {
            // keep SecretTy from being dyn-compatible
            self
        }

        fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata);
        fn from_raw_parts(ptr: *mut (), meta: Self::Metadata) -> *mut Self;
    }
}

use core::iter::FusedIterator;

use bytemuck::{Pod, TransparentWrapper};
use private::{ArrayChunks, Sealed};

pub trait Remainder<'a>: 'a + Sealed {
    fn remainder(&self) -> &'a [u8];
}

impl<'a, T: 'a + Copy, const N: usize> Sealed for ArrayChunks<'a, T, N> {}

impl<'a, const N: usize> Remainder<'a> for ArrayChunks<'a, u8, N> {
    fn remainder(&self) -> &'a [u8] {
        self.0.remainder()
    }
}

pub trait ByteArray: Sealed + Pod + Eq + AsRef<[u8]> + AsMut<[u8]> + SecretTy + 'static {
    const LEN: usize;
    type ArrayChunks<'a>: Iterator<Item = &'a Self>
        + ExactSizeIterator
        + DoubleEndedIterator
        + FusedIterator
        + Remainder<'a>
        + 'a
    where
        Self: 'a;

    fn array_chunks<'a>(sl: &'a [u8]) -> Self::ArrayChunks<'a>;

    fn last_mut(&mut self) -> &mut u8 {
        const {
            assert!(Self::LEN > 0);
        }

        &mut self.as_mut()[(Self::LEN) - 1]
    }

    fn last_chunk_mut<const N: usize>(&mut self) -> &mut [u8; N] {
        const {
            assert!(N <= Self::LEN);
        }

        let x = Self::LEN - N;

        unsafe { &mut *(&raw mut self.as_mut()[x..]).cast() }
    }

    fn extend(sl: &[u8]) -> Self {
        assert!(sl.len() <= Self::LEN);

        let mut this: Self = bytemuck::zeroed();

        let len = sl.len();

        this.as_mut().copy_from_slice(sl);

        this
    }

    fn truncate(sl: &[u8]) -> Self {
        assert!(Self::LEN <= sl.len());
        let mut this: Self = bytemuck::zeroed();
        bytemuck::bytes_of_mut(&mut this).copy_from_slice(&sl[..Self::LEN]);
        this
    }
}

impl<const N: usize> Sealed for [u8; N] {}
impl<const N: usize> ByteArray for [u8; N] {
    const LEN: usize = N;

    type ArrayChunks<'a> = private::ArrayChunks<'a, u8, N>;

    fn array_chunks<'a>(sl: &'a [u8]) -> Self::ArrayChunks<'a> {
        const {
            assert!(N != 0);
        }
        private::ArrayChunks(sl.array_chunks())
    }
}

#[doc(hidden)]
pub use private::SealedSecret;

use crate::mem::transmute_unchecked;

/// [`SecretTy`] is a type that can be used with [`Secret<T>`][crate::secret::Secret]
///
/// This is a sealed trait and cannot be implemented outside of the trait
///
/// ## Safety
/// Every implementor of this trait guarantees the following:
/// * It can be safely cast to an from a (potentially mutable) slice of bytes with length equal to `size_of_val`
/// * A mutable value of the type can be overwitten with all zeroes.
/// * If `Self: Sized`, then `Self: Copy + Pod`.
pub unsafe trait SecretTy: SealedSecret {}

impl<T: Pod + Eq> SealedSecret for T {
    type Metadata = ();

    fn from_raw_parts(ptr: *mut (), _: Self::Metadata) -> *mut Self {
        ptr.cast()
    }

    fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata) {
        (ptr.cast(), ())
    }
}
unsafe impl<T: Pod + Eq> SecretTy for T {}

impl<T: SealedSecret> SealedSecret for [T] {
    type Metadata = usize;

    fn from_raw_parts(ptr: *mut (), meta: Self::Metadata) -> *mut Self {
        core::ptr::slice_from_raw_parts_mut(ptr.cast(), meta)
    }

    fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata) {
        let len = ptr.len();

        (ptr.cast(), len)
    }
}
unsafe impl<T: SecretTy> SecretTy for [T] {}

pub unsafe trait SecretSlice: TransparentWrapper<[Self::ElemTy]> {
    type ElemTy: SecretTy;
}

#[doc(hidden)]
pub trait SecretSliceCheck {
    const __TEST: ();
}

impl<S: ?Sized + SecretSlice> SecretSliceCheck for S {
    const __TEST: () = const {
        assert!(
            core::mem::size_of::<*const S>()
                == core::mem::size_of::<*const [<S as SecretSlice>::ElemTy]>()
        );
    };
}

#[macro_export]
macro_rules! secret_slice_wrap {
    (for<$($life:lifetime),* $($name:ident),* $(,)?> $ty:ty) => {
        impl <$($life),* $($name),*> $crate::traits::SealedSecret for $ty {
            type Metadata = usize;

            fn from_raw_parts(ptr: *mut (), meta: usize) -> *mut Self {
                const { <Self as $crate::traits::SecretSliceCheck>::__TEST;}
                let v = <[<Self as $crate::traits::SecretSlice>::ElemTy] as $crate::traits::SecretTy>::from_raw_parts(ptr, meta);

                v as *mut Self;
            }

            fn into_raw_parts(ptr: *mut Self) -> (*mut (), usize) {
                const { <Self as $crate::traits::SecretSliceCheck>::__TEST;}
                let v = ptr as *mut [<Self as $crate::traits::SecretSlice>::ElemTy];

                $crate::traits::SecretTy::into_raw_parts(v)
            }
        }

        impl <$($life),* $($name),*> $crate::traits::SecretTy for $ty{}
    };
    ($ty:ty) => {
        impl $crate::traits::SealedSecret for $ty {
            type Metadata = usize;
            fn from_raw_parts(ptr: *mut (), meta: usize) -> *mut Self {
                const { <Self as $crate::traits::SecretSliceCheck>::__TEST }
                let v = <[<Self as $crate::traits::SecretSlice>::ElemTy] as $crate::traits::SealedSecret>::from_raw_parts(ptr, meta);

                v as *mut Self
            }

            fn into_raw_parts(ptr: *mut Self) -> (*mut (), usize) {
                const { <Self as $crate::traits::SecretSliceCheck>::__TEST }
                let v = ptr as *mut [<Self as $crate::traits::SecretSlice>::ElemTy];

                $crate::traits::SealedSecret::into_raw_parts(v)
            }
        }

        unsafe impl  $crate::traits::SecretTy for $ty{}
    };
}
