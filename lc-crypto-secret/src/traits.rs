mod private {
    pub trait Sealed {
        fn foo(&self) -> &Self {
            // keep SecretTy from being dyn-compatible
            self
        }
    }
}

use bytemuck::Pod;
use private::Sealed;

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

impl<T: Pod + Eq> Sealed for T {}
impl<T: Pod + Eq> SecretTy for T {}

impl<T: Sealed> Sealed for [T] {}
impl<T: SecretTy> SecretTy for [T] {}
