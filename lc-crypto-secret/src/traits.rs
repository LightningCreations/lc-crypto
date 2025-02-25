mod private {
    pub trait Sealed {
        type Metadata: Sized + Copy + Eq;
        fn foo(&self) -> &Self {
            // keep SecretTy from being dyn-compatible
            self
        }

        fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata);
        fn from_raw_parts(ptr: *mut (), meta: Self::Metadata) -> *mut Self;
    }
}

use bytemuck::Pod;
pub(crate) use private::Sealed;

/// [`SecretTy`] is a type that can be used with [`Secret<T>`][crate::secret::Secret]
///
/// This is a sealed trait and cannot be implemented outside of the trait
///
/// ## Safety
/// Every implementor of this trait guarantees the following:
/// * It can be safely cast to an from a (potentially mutable) slice of bytes with length equal to `size_of_val`
/// * A mutable value of the type can be overwitten with all zeroes.
/// * If `Self: Sized`, then `Self: Copy + Pod`.
pub trait SecretTy: Sealed {}

impl<T: Pod + Eq> Sealed for T {
    type Metadata = ();

    fn from_raw_parts(ptr: *mut (), _: Self::Metadata) -> *mut Self {
        ptr.cast()
    }

    fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata) {
        (ptr.cast(), ())
    }
}
impl<T: Pod + Eq> SecretTy for T {}

impl<T: Sealed> Sealed for [T] {
    type Metadata = usize;

    fn from_raw_parts(ptr: *mut (), meta: Self::Metadata) -> *mut Self {
        core::ptr::slice_from_raw_parts_mut(ptr.cast(), meta)
    }

    fn into_raw_parts(ptr: *mut Self) -> (*mut (), Self::Metadata) {
        let len = ptr.len();

        (ptr.cast(), len)
    }
}
impl<T: SecretTy> SecretTy for [T] {}
