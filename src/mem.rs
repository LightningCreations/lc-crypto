use core::mem::{ManuallyDrop, MaybeUninit};

use bytemuck::Zeroable;

use crate::{asm::write_bytes_explicit, traits::ByteArray};

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

#[inline]
pub fn explicit_zero_in_place<T: ZeroableInPlace + ?Sized>(val: &mut T) {
    let count = core::mem::size_of_val(val);

    unsafe {
        write_bytes_explicit(val as *mut T as *mut u8, 0, count);
    }
}

#[inline(always)]
pub fn zero_in_place<T: ZeroableInPlace + ?Sized>(val: &mut T) {
    let count = core::mem::size_of_val(val);
    unsafe {
        core::ptr::write_bytes(val as *mut T as *mut u8, 0, count);
    }
}

#[inline(always)]
pub const fn as_slice<A: ByteArray>(x: &A) -> &[u8] {
    unsafe { core::slice::from_raw_parts(x as *const A as *const u8, A::LEN) }
}

#[inline(always)]
pub const fn as_slice_mut<A: ByteArray>(x: &mut A) -> &mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(x as *mut A as *mut u8, A::LEN) }
}

#[inline]
pub fn copy_from_slice_truncate<T: Copy>(dest: &mut [T], src: &[T]) {
    let true_len = dest.len().min(src.len());

    dest[..true_len].copy_from_slice(&src[..true_len]);
}
