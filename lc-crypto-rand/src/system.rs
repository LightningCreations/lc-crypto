#[cfg(any(doc, target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

#[cfg(any(unix, windows, target_os = "lilium"))]
pub mod os;
