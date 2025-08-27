//! Provides low level implementations of routines that need special handling to use on secret data
//! The module is called `asm` because many routines (when implemented properly) require the use of asm.
//!
//! ## Side Channel Avoidance
//! These routines are written in such a way that they avoid timing side channel attacks.
//! Due to implementation constraints, this is current only guaranteed on a subset of targets.
//! The remaining targets are guaranteed only on a best-effort basis, where compiler optimizations may create unexpected side channels.
//! This is due to lack of asm implementations of these routines
//!
//! All routines are currently supported side-channel free on:
//! * x86_64

use core::mem::ManuallyDrop;

/// Compares bytes starting from `a` and `b` up to `len` for equality only.
/// The routine will access (and compare) all `len` bytes and will not short-circuit when it finds an unequal byte.
///
/// # Safety
/// `a` and `b` must both be readable for `len` bytes. `
#[inline]
pub unsafe fn eq_bytes_secure(a: *const u8, b: *const u8, len: usize) -> bool {
    let mut res: u8;
    cfg_match::cfg_match! {
        target_arch = "x86_64" => unsafe {
        let is_sse = crate::is_x86_feature_detected!("sse4.1");
        let is_avx = crate::is_x86_feature_detected!("avx");
        core::arch::asm!{
                "xor eax, eax",
                "mov r8, 1",
                "cmp rcx, 8",
                "jb 3f",
                "2:",
                "mov rdx, qword ptr [rdi]",
                "cmp rdx, qword ptr [rsi]",
                "cmovne rax, r8",
                "lea rdi, [rdi+8]",
                "lea rsi, [rsi+8]",
                "lea rcx, [rcx-8]",
                "cmp rcx, 8",
                "jae 2b",
                "3:",
                "cmp rcx, 4",
                "jb 3f",
                "mov edx, dword ptr [rdi]",
                "cmp edx, dword ptr [rsi]",
                "cmovne rax, r8",
                "lea rdi, [rdi+4]",
                "lea rsi, [rsi+4]",
                "lea rcx, [rcx-4]",
                "3:",
                "cmp rcx, 2",
                "jb 3f",
                "mov dx, word ptr [rdi]",
                "cmp dx, word ptr [rsi]",
                "cmovne rax, r8",
                "lea rdi, [rdi+2]",
                "lea rsi, [rsi+2]",
                "lea rcx, [rcx-2]",
                "3:",
                "cmp rcx, 1",
                "jb 3f",
                "mov dl, byte ptr [rdi]",
                "cmp dl, byte ptr [rsi]",
                "cmovne rax, r8",
                "3:",
                inout("rdi") a=> _,
                inout("rsi") b=> _,
                inout("rcx") len => _,
                out("rdx") _,
                out("al") res,
                out("r8") _,
                out("xmm0") _,
                out("xmm1") _,
                options(nostack, readonly, pure),
            }
    },
        // target_arch = "x86" => unsafe { core::arch::asm!{
        //     "xor eax, eax",
        //     "cmp ecx, 4",
        //     "jb 3f",
        //     "2:",
        //     "mov edx, dword ptr [edi]",
        //     "cmp edx, dword ptr [esi]",
        //     "setne al",
        //     "lea edi, [edi+4]",
        //     "lea esi, [esi+4]",
        //     "lea ecx, [ecx-4]",
        //     "cmp ecx, 8",
        //     "jae 2b",
        //     "3:",
        //     "cmp ecx, 2",
        //     "jb 3f",
        //     "mov dx, word ptr [edi]",
        //     "cmp dx, word ptr [esi]",
        //     "setne al",
        //     "lea edi, [edi+2]",
        //     "lea esi, [esi+2]",
        //     "lea ecx, [ecx-2]",
        //     "3:",
        //     "cmp ecx, 1"
        //     "jb 3f",
        //     "cmp ecx, 4",
        //     "jb 3f",
        //     "mov dl, byte ptr [edi]",
        //     "cmp dl, byte ptr [esi]",
        //     "setne al",
        //     inout("edi") a=> _,
        //     inout("esi") b=> _,
        //     inout("ecx") len => _,
        //     out("edx") _,
        //     out("eax") res,
        //     options(nostack, readonly, pure),
        // } },

        _ => {
            res = 0;

            unsafe{let _ = a.add(len);}
            unsafe{let _ = b.add(len);}

            // black_box may not be perfect for preventing side channels, but it's as good as it gets
            for i in 0..len {
                res = core::hint::black_box(res | (unsafe{a.add(i).volatile_read() != b.add(i).volatile_read()}))
            }
        }
    }

    // res is "Are the bytes unequal anywhere"
    !unsafe { core::mem::transmute(res) }
}

/// Overwrites `len` bytes starting from `a` with all `val` bytes.
/// The call will not be elided due to being dead (but may in the future be elided if the entire buffer is never accessed)
#[inline]
pub unsafe fn write_bytes_explicit(a: *mut u8, val: u8, len: usize) {
    let splat = usize::from_ne_bytes([val; core::mem::size_of::<usize>()]);

    cfg_match::cfg_match! {
        target_arch = "x86_64" => unsafe {
            let splat_xmm = ::core::arch::x86_64::_mm_set_epi64x(splat as i64, splat as i64);
            core::arch::asm!{
                "cmp rcx, 16",
                "jb 3f",
                "2:",
                "movdqu xmmword ptr [rdi], xmm0",
                "lea rdi, [rdi+16]",
                "lea rcx, [rcx-16]",
                "cmp rcx, 16",
                "jae 2b",
                "3:",
                "cmp rcx, 8",
                "jb 3f",
                "mov qword ptr [rdi], rax",
                "lea rdi, [rdi+8]",
                "lea rcx, [rcx-8]",
                "3:",
                "cmp rcx, 4",
                "jb 3f",
                "mov dword ptr [rdi], eax",
                "lea rdi, [rdi+4]",
                "lea rcx, [rcx-4]",
                "3:",
                "cmp rcx, 2",
                "jb 3f",
                "mov word ptr [rdi], ax",
                "lea rdi, [rdi+2]",
                "lea rcx, [rcx-2]",
                "3:",
                "cmp rcx, 1",
                "jb 3f",
                "mov byte ptr [rdi], al",
                "3:",
                inout("rdi") a => _,
                inout("rcx") len => _,
                in("rax") splat,
                in("xmm0") splat_xmm,
                options(nostack),
            }
        } ,
        _ => {
            let _ = unsafe{a.add(len)};

            for i in 0..len {
                unsafe{a.add(i).write_volatile(len)}
            }
        }
    }
}

/// Computes `ptr.add(b)` but avoids allowing the compiler to make assumptions about what value of `b` computes the return pointer.
///
/// The call fails to compile if `T` is a ZST.
///
/// # Safety
///
/// The same requirements as [`<*const T>::add`][`pointer::add`], in particular:
/// * `b * core::mem::size_of::<T>()` must not exceed `isize::MAX as usize`
/// * Adding `b` to `ptr` must result in a pointer that is inbounds of the same allocation as `ptr`, and
/// * Adding `b` to `ptr` must not wrap arround the address space.
///
/// Note that while the compiler may not assume the particular value of `b`, it's allowed to assume that `b` is a value that satisfies the above constraints.
#[cfg_attr(
    all(doc, not(feature = "nightly-docs")),
    doc = "[`pointer::add`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.add"
)]
#[inline(always)]
pub unsafe fn add_unpredicatable<T>(b: usize, ptr: *const T) -> *const T {
    const { assert!(core::mem::size_of::<T>() != 0) }
    let ret: *const T;
    cfg_match::cfg_match! {
        target_arch = "x86_64"  => unsafe {
            if const {core::mem::size_of::<T>().is_power_of_two()} {
                if const {core::mem::size_of::<T>() == 1 || core::mem::size_of::<T>() == 2 || core::mem::size_of::<T>() == 4 || core::mem::size_of::<T>() == 8 } {
                    core::arch::asm!{
                        "lea {out}, [{ptr} + {SIZE}*{b}]",
                        ptr = in(reg) ptr,
                        b = in(reg) b as usize,
                        out = lateout(reg) ret,
                        SIZE = const core::mem::size_of::<T>(),
                        options(nostack, nomem, pure, preserves_flags)
                    }
                } else {
                    core::arch::asm!{
                        "shl {b}, {SIZE_BITS}",
                        "lea {out}, [{ptr} + {b}]",
                        ptr = in(reg) ptr,
                        b = inout(reg) b as usize => _,
                        out = lateout(reg) ret,
                        SIZE_BITS = const const { core::mem::size_of::<T>().trailing_zeros() },
                        options(nostack, nomem, pure)
                    }
                }
            } else {
                core::arch::asm! {
                    "imul {b}, {b}, {SIZE}",
                    "lea {out}, [{ptr} + {b}]",
                    ptr = in(reg) ptr,
                    b = inout(reg) b as usize => _,
                    out = lateout(reg) ret,
                    SIZE = const core::mem::size_of::<T>(),
                    options(nostack, nomem, pure)
                }
            }
        },
        _ => {
            ret = ptr.add(core::hint::black_box(b));
        }
    }

    let _ = unsafe { ptr.offset_from(ret) }; // Asserts to the compiler that they belong to the same allocation, and are a whole number of `T` steps away from each other

    ret
}

/// Performs an "SBOX" Lookup using `sbox_ptr` and the SBOX input `b`.
///
/// # Safety
///
/// Regardless of `b`, `sbox_ptr` must be dereferenceable for 256 bytes
pub unsafe fn sbox_lookup(b: u8, sbox_ptr: *const [u8; 256]) -> u8 {
    let val: u8;
    cfg_match::cfg_match! {
        target_arch = "x86_64" => unsafe {
            let mut buf: u64;

            core::arch::asm!{
                "2:",
                "mov {scratch}, qword ptr [{ptr}]",
                "cmp {off:l}, 0",
                "cmove {res}, {scratch}",
                "mov {scratch}, qword ptr [{ptr}+8]",
                "cmp {off:l}, 1",
                "cmove {res}, {scratch}",
                "mov {scratch}, qword ptr [{ptr}+16]",
                "cmp {off:l}, 2",
                "cmove {res}, {scratch}",
                "mov {scratch}, qword ptr [{ptr}+24]",
                "cmp {off:l}, 3",
                "cmove {res}, {scratch}",
                "lea {off}, [{off}-4]",
                "lea {ptr}, [{ptr}+32]",
                "dec {ctr:e}",
                "jne 2b",
                scratch = out(reg) _ ,
                off = inout(reg) (b>>3) as usize=>_,
                ptr = inout(reg) sbox_ptr=>_,
                res = out(reg) buf,
                ctr = inout(reg) 8=>_,
                options(nostack, readonly, pure)
            }

            val = ((buf) >> 8 *((b&0x7) as u32)) as u8;
        },
        _ => {
            let mut scratch = 0usize;
            let ptr = sbox_ptr.cast::<usize>();

            let _ = unsafe{sbox_ptr.add(256)};

            let (idx, pos) = core::hint::black_box(((b as usize)/core::mem::size_of::<usize>(), (b as usize)%core::mem::size_of::<usize>()));

            for i in 0..(256/core::mem::size_of::<usize>()) {
                let mask = core::hint::black_box(((i == idx) as usize).wrapping_sub(1));

                scratch = core::hint::black_box(core::hint::black_box(scratch & mask) | core::hint::black_box(unsafe{ptr.add(i).read_unaligned()} & !mask));
            }

            val = ((scratch) >> 8 *(pos as u32)) as u8;
        }
    }

    val
}
