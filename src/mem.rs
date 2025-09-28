use core::mem::{ManuallyDrop, MaybeUninit};

use bytemuck::Zeroable;

use crate::asm::write_bytes_explicit;

///
/// Marker trait for a (potentially-unsized) type that can be zeroed in place
pub unsafe trait ZeroableInPlace {}

unsafe impl<Z: Zeroable> ZeroableInPlace for Z {}

unsafe impl<Z: ZeroableInPlace> ZeroableInPlace for [Z] {}

#[repr(C)]
union Transmuter<T, U> {
    x: ManuallyDrop<T>,
    y: ManuallyDrop<U>,
}

#[inline(always)]
pub const unsafe fn transmute_unchecked<T, U>(x: T) -> U {
    ManuallyDrop::into_inner(unsafe {
        Transmuter {
            x: ManuallyDrop::new(x),
        }
        .y
    })
}

#[inline(always)]
pub fn explicit_zero_in_place<T: ZeroableInPlace + ?Sized>(val: &mut T) {
    let count = core::mem::size_of_val(val);

    unsafe {
        write_bytes_explicit(val as *mut T as *mut u8, 0, count);
    }
}

#[inline(always)]
pub fn zero_in_place<T: ZeroableInPlace + ?Sized>(val: &mut T) {}
