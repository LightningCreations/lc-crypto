use cfg_match::cfg_match;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(
        all(target_feature = "rdrand", feature = "allow-weak-hw-rand"),
        target_feature = "rdseed"
    )
))]
pub mod x86;

#[cfg(target_os = "linux")]
pub mod linux;

cfg_match! {
    all(feature = "hardware-rand", all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(
            all(target_feature = "rdrand", feature = "allow-weak-hw-rand"),
            target_feature = "rdseed"
        )
    )) => {pub use x86::X86Rand as SystemRand;}
    target_os = "linux" => { pub use linux::LinuxRand as SystemRand;}
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(
            all(target_feature = "rdrand", feature = "allow-weak-hw-rand"),
            target_feature = "rdseed"
        )
    ) => {pub use x86::X86Rand as SystemRand;}
    _ => {}
}
