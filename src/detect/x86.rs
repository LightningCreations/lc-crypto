#[cfg(feature = "runtime-detect")]
use spin::once::Once;

// Contains the feature array.
// The layout of the array is as follows:
// 0. cpuid[eax=1].ecx
// 1. cpuid[eax=1].edx
// 2. cpuid[eax=7,ecx=0].ecx
// 3. cpuid[eax=7,ecx=0].edx
// 4. cpuid[eax=7,ecx=0].ebx
// 5. cpuid[eax=7,ecx=1].eax
// 6. cpuid[eax=7,ecx=1].ecx
// 7. cpuid[eax=7,ecx=1].edx
// 8. cpuid[eax=7,ecx=1].ebx
// 9. cpuid[eax=7,ecx=2].eax
// 10. cpuid[eax=7,ecx=2].ecx
// 11. cpuid[eax=7,ecx=2].edx
// 12. Reserved
// 13. Reserved
// 14. cpuid[eax=0x80000001].ecx*
// 15. cpuid[eax=0x80000001].edx
// 16. cpuid[eax=0x24,ecx=0].ebx
// 32. cpuid[eax=0x0D, ecx=0].eax
// 33. cpuid[eax=0x0D, ecx=0].edx
// 34. cpuid[eax=0x0D,ecx=0].ecx
// 35. cpuid[eax=0x0D,ecx=1].eax
//
// Reserved fields are set to `0` in the described version of the Kernel. The value may be changed in future versions and must not be relied upon by the Software.
//
// ## Notes about Extended Processor Info (cpuid[eax=0x80000001])
// The value set in `cpu_feature_info[14]` does not exactly match the content of the `ecx` register after a `cpuid` instruction for that leaf,
//  specifically the following differences are observed:
// * Bits 0-9, 12-17, 23, and 24, which are mirrors of the same bits in `cpuid[eax=1].ecx` (`cpu_feature_info[0]`) on AMD Processors only, are set to `0` regardless of the processor,
// * Bit 10, which indicates `syscall` support on the AMD k6 processor only, is clear,
// * Bit 11, which indicates `syscall` support, is set to `1` on an AMD k6 processor that indicates support via `cpuid[eax=0x80000001].ecx[10]`, and
// * Bit 11 may be set to `0` if executed from a 32-bit process running on a 64-bit OS, even if `cpuid` would report it's support.
#[cfg(feature = "runtime-detect")]
static CPU_FEATURE_INFO: Once<[u32; 36]> = Once::new();

#[cfg(feature = "runtime-detect")]
fn init_cpuid_features() -> [u32; 36] {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{__cpuid, __cpuid_count};

    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    const fn select_mask(sel: bool, mask: u32) -> u32 {
        if sel { u32::MAX } else { !mask }
    }

    {
        let cpuid_eax1 = __cpuid(1);
        let cpuid_eax7_ecx0 = __cpuid_count(7, 0);
        let cpuid_eax7_ecx1 = if cpuid_eax7_ecx0.eax >= 1 {
            __cpuid_count(7, 1)
        } else {
            unsafe { core::mem::zeroed() }
        };
        let cpuid_eax7_ecx2 = if cpuid_eax7_ecx0.eax >= 2 {
            __cpuid_count(7, 2)
        } else {
            unsafe { core::mem::zeroed() }
        };
        let cpuidx_eaxe1 = __cpuid(0x80000001);
        let cpuid_eaxD_ecx0 = __cpuid_count(0xD, 0);
        let cpuid_eaxD_ecx1 = __cpuid_count(0x0D, 1);
        let cpuid_eax24_ecx0 = __cpuid_count(0x24, 0);
        let cpuid_eax24_ecx1 = __cpuid_count(0x24, 1);

        let enable_osxsave = (cpuid_eax1.ecx & (1 << 27)) != 0;

        let getbv = if enable_osxsave {
            let lo: u64;
            let hi: u64;
            unsafe { core::arch::asm!("xgetbv", in("rcx") 0, out("rax") lo, out("rdx") hi) };

            (hi << 32) | lo
        } else {
            0
        };

        let use_avx512 = (getbv & (0b111 << 5)) == (0b111 << 5);
        let use_avx = (getbv & (1 << 2)) != 0;
        let use_apx = (getbv & (1 << 19)) != 0;

        let avx_mask_eax1_ecx = (1 << 28);
        let avx_mask_eax7_ec0_ebx = (1 << 5);

        let apx_mask_eax7_ecx1_edx = (1 << 21);

        let avx512_mask_eax7_ecx0_ecx = (1 << 1) | (1 << 6) | (1 << 11) | (1 << 12) | (1 << 14);
        let avx512_mask_eax7_ecx0_edx = (1 << 2) | (1 << 3) | (1 << 8) | (1 << 23);
        let avx512_mask_eax7_ecx0_ebx =
            (1 << 16) | (1 << 17) | (1 << 21) | (1 << 26) | (1 << 28) | (1 << 30) | (1 << 31);
        let avx512_mask_eax7_ecx1_eax = (1 << 5);

        let arr = [
            cpuid_eax1.ecx & select_mask(use_avx, avx_mask_eax1_ecx),
            cpuid_eax1.edx,
            cpuid_eax7_ecx0.ecx & select_mask(use_avx512, avx512_mask_eax7_ecx0_ecx),
            cpuid_eax7_ecx0.edx & select_mask(use_avx512, avx512_mask_eax7_ecx0_edx),
            cpuid_eax7_ecx0.ebx
                & select_mask(use_avx, avx_mask_eax7_ec0_ebx)
                & select_mask(use_avx512, avx512_mask_eax7_ecx0_ebx),
            cpuid_eax7_ecx1.eax & select_mask(use_avx512, avx512_mask_eax7_ecx1_eax),
            cpuid_eax7_ecx1.ecx,
            cpuid_eax7_ecx1.edx & select_mask(use_apx, apx_mask_eax7_ecx1_edx),
            cpuid_eax7_ecx1.ebx,
            cpuid_eax7_ecx2.eax,
            cpuid_eax7_ecx2.ecx,
            cpuid_eax7_ecx2.edx,
            0,
            0,
            cpuidx_eaxe1.ecx,
            cpuidx_eaxe1.edx,
            cpuid_eax24_ecx0.ebx,
            cpuid_eax24_ecx1.ecx,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            cpuid_eaxD_ecx0.eax,
            cpuid_eaxD_ecx0.edx,
            cpuid_eaxD_ecx1.eax,
            0,
        ];

        arr
    }
}

#[cfg(feature = "runtime-detect")]
#[doc(hidden)]
pub fn __get_cpuid_features() -> &'static [u32; 36] {
    CPU_FEATURE_INFO.call_once(init_cpuid_features)
}

#[macro_export]
#[doc(hidden)]
macro_rules! __x86_feature_to_bit {
    ("x87") => {
        (1, 0)
    };
    ("cmpxchg8b") => {
        (1, 8)
    };
    ("cmpxchg16b") => {
        (0, 16)
    };
    ("rdrand") => {
        (0, 30)
    };
    ("rdseed") => {
        (2, 18)
    };
    ("tsc") => {
        (1, 4)
    };
    ("msr") => {
        (1, 5)
    };
    ("apic") => {
        (1, 9)
    };
    ("sep") => {
        (1, 11)
    };
    ("mtrr") => {
        (1, 12)
    };
    ("pge") => {
        (1, 13)
    };
    ("cmov") => {
        (1, 15)
    };
    ("pat") => {
        (1, 16)
    };
    ("mmx") => {
        (1, 23)
    };
    ("fxsr") => {
        (1, 24)
    };
    ("sse") => {
        (1, 25)
    };
    ("sse2") => {
        (1, 26)
    };
    ("sse3") => {
        (0, 0)
    };
    ("pclmulqdq") => {
        (0, 1)
    };
    ("monitor") => {
        (0, 3)
    };
    ("vmx") => {
        (0, 5)
    };
    ("smx") => {
        (0, 6)
    };
    ("ssse3") => {
        (0, 9)
    };
    ("fma") => {
        (0, 12)
    };
    ("pcid") => {
        (0, 17)
    };
    ("sse4.1") => {
        (0, 19)
    };
    ("sse4.2") => {
        (0, 20)
    };
    ("movbe") => {
        (0, 22)
    };
    ("popcnt") => {
        (0, 23)
    };
    ("aes") => {
        (0, 25)
    };
    ("xsave") => {
        (0, 26)
    };
    ("avx") => {
        (0, 28)
    };
    ("f16c") => {
        (0, 29)
    };
    ("pretetchwt1") => {
        (2, 0)
    };
    ("avx512-vbmi") => {
        (2, 1)
    };
    ("umip") => {
        (2, 2)
    };
    ("pku") => {
        (2, 3)
    };
    ("waitpkg") => {
        (2, 5)
    };
    ("avx512-vbmi2") => {
        (2, 6)
    };
    ("shstk") => {
        (2, 7)
    };
    ("gfni") => {
        (2, 8)
    };
    ("vaes") => {
        (2, 9)
    };
    ("avx512-vnni") => {
        (2, 11)
    };
    ("avx512-bitalg") => {
        (2, 12)
    };
    ("tme_en") => {
        (2, 13)
    };
    ("avx512-vpopcntdq") => {
        (2, 14)
    };
    ("la57") => {
        (2, 16)
    };
    ("rdpid") => {
        (2, 22)
    };
    ("kl") => {
        (2, 23)
    };
    ("movdiri") => {
        (2, 27)
    };
    ("movdir64b") => {
        (2, 28)
    };
    ("enqcmd") => {
        (2, 29)
    };
    ("sgx-lc") => {
        (2, 30)
    };
    ("pks") => {
        (2, 31)
    };
    ("sgx-keys") => {
        (3, 1)
    };
    ("avx512-4vnniw") => {
        (3, 2)
    };
    ("avx512-4fmaps") => {
        (3, 3)
    };
    ("fsrm") => {
        (3, 4)
    };
    ("uintr") => {
        (3, 5)
    };
    ("avx512-vp2intersect") => {
        (3, 8)
    };
    ("serialize") => {
        (3, 14)
    };
    ("pconfig") => {
        (3, 18)
    };
    ("cet-ibt") => {
        (3, 20)
    };
    ("amx-bf16") => {
        (3, 22)
    };
    ("avx512-fp16") => {
        (3, 23)
    };
    ("amx-tile") => {
        (3, 24)
    };
    ("amx-int8") => {
        (3, 25)
    };
    ("fsgsbase") => {
        (4, 0)
    };
    ("sgx") => {
        (4, 2)
    };
    ("bmi1") => {
        (4, 3)
    };
    ("hle") => {
        (4, 4)
    };
    ("avx2") => {
        (4, 5)
    };
    ("smep") => {
        (4, 7)
    };
    ("bmi2") => {
        (4, 8)
    };
    ("erms") => {
        (4, 9)
    };
    ("invpcid") => {
        (4, 10)
    };
    ("rtm") => {
        (4, 11)
    };
    ("mpx") => {
        (4, 14)
    };
    ("avx512f") => {
        (4, 16)
    };
    ("avx512dq") => {
        (4, 17)
    };
    ("adx") => {
        (4, 19)
    };
    ("smap") => {
        (4, 20)
    };
    ("avx512-ifma") => {
        (4, 21)
    };
    ("clflushopt") => {
        (4, 23)
    };
    ("clwb") => {
        (4, 24)
    };
    ("avx512pf") => {
        (4, 26)
    };
    ("avx512er") => {
        (4, 27)
    };
    ("avx512cd") => {
        (4, 28)
    };
    ("sha") => {
        (4, 29)
    };
    ("avx512bw") => {
        (4, 30)
    };
    ("avx512vl") => {
        (4, 31)
    };
    ("sha512") => {
        (5, 0)
    };
    ("sm3") => {
        (5, 1)
    };
    ("sm4") => {
        (5, 2)
    };
    ("rao-int") => {
        (5, 3)
    };
    ("avx-vnni") => {
        (5, 4)
    };
    ("avx512-bf16") => {
        (5, 5)
    };
    ("lass") => {
        (5, 6)
    };
    ("cmpccxadd") => {
        (5, 7)
    };
    ("fzrm") => {
        (5, 11)
    };
    ("rsrcs") => {
        (5, 12)
    };
    ("fred") => {
        (5, 17)
    };
    ("lkgs") => {
        (5, 18)
    };
    ("wrmsrns") => {
        (5, 19)
    };
    ("nmi_src") => {
        (5, 20)
    };
    ("amx-fp16") => {
        (5, 21)
    };
    ("hreset") => {
        (5, 22)
    };
    ("avx-ifma") => {
        (5, 23)
    };
    ("lam") => {
        (5, 26)
    };
    ("msrlist") => {
        (5, 27)
    };
    ("legacy_reduced_isa") => {
        (6, 2)
    };
    ("sipi64") => {
        (6, 4)
    };
    ("avx-vnni-int8") => {
        (7, 4)
    };
    ("avx-ne-convert") => {
        (7, 5)
    };
    ("amx-complex") => {
        (7, 8)
    };
    ("avx-vnni-int16") => {
        (7, 10)
    };
    ("utmr") => {
        (7, 13)
    };
    ("prefetchi") => {
        (7, 14)
    };
    ("user_msr") => {
        (7, 15)
    };
    ("cet-sss") => {
        (7, 18)
    };
    ("avx10") => {
        (7, 19)
    };
    ("apx") => {
        (7, 21)
    };
    ("mwait") => {
        (7, 23)
    };
    ("pbndkb") => {
        (8, 1)
    };
    ("lahf_lm") => {
        (14, 0)
    };
    ("svm") => {
        (14, 2)
    };
    ("cr8_legacy") => {
        (14, 4)
    };
    ("abm") => {
        (14, 5)
    };
    ("sse4a") => {
        (14, 6)
    };
    ("3dnowprefetch") => {
        (14, 8)
    };
    ("xop") => {
        (14, 11)
    };
    ("skinit") => {
        (14, 12)
    };
    ("fma4") => {
        (14, 16)
    };
    ("tbm") => {
        (14, 21)
    };
    ("monitorx") => {
        (14, 29)
    };
    ("syscall") => {
        (15, 11)
    };
    ("nx") => {
        (15, 20)
    };
    ("mmxext") => {
        (15, 22)
    };
    ("fxsr_opt") => {
        (15, 25)
    };
    ("pdpe1gb") => {
        (15, 26)
    };
    ("rdtscp") => {
        (15, 27)
    };
    ("lm") => {
        (15, 29)
    };
    ("3dnowext") => {
        (15, 30)
    };
    ("3dnow") => {
        (15, 31)
    };
    ("avx10-128") => {
        (16, 16)
    };
    ("avx10-256") => {
        (16, 17)
    };
    ("avx10-512") => {
        (16, 18)
    };
    ("xsaveopt") => {
        (34, 0)
    };
    ("xsavec") => {
        (34, 1)
    };
    ("xgetbv_ecx1") => {
        (34, 2)
    };
    ("xss") => {
        (34, 3)
    };
    ("xfd") => {
        (34, 4)
    };
    ($feat:literal) => {
        ::core::compile_error!(::core::concat!("Unknown feature ", $feat))
    };
}

#[macro_export]
macro_rules! is_x86_feature_enabled {
    ($feature:tt) => {
        const {
            let _ = $crate::__x86_feature_to_bit!($feature);
            ::core::cfg!(target_feature = $feature)
        }
    };
}

#[cfg(feature = "runtime-detect")]
#[macro_export]
macro_rules! is_x86_feature_detected {
    ($feature:tt) => {
        $crate::is_x86_feature_enabled!($feature)
            || ({
                let (idx, bit) = $crate::__x86_feature_to_bit!($feature);
                ($crate::detect::x86::__get_cpuid_features())[idx] & (1 << bit) != 0
            })
    };
}

#[cfg(not(feature = "runtime-detect"))]
#[macro_export]
macro_rules! is_x86_feature_detected {
    ($feature:tt) => {
        $crate::is_x86_feature_enabled!($feature)
    };
}
