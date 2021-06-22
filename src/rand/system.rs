#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(target_feature = "rdrand", target_feature = "rdseed")
))]
mod x86;

#[cfg(target_os = "linux")]
mod linux;
