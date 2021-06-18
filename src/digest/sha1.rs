#[cfg(target_arch = "x86_64")]
mod x86_64;

pub struct Sha1 {
    h: [u32; 5],
}
