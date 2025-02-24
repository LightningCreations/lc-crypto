use core::mem::{ManuallyDrop, MaybeUninit};

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
