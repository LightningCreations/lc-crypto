use lc_crypto_primitives::rand::CsRand;

pub struct X86Rand;

impl X86Rand {
    fn poll_word(&self) -> usize {
        let mut val = 0;
        while (cfg_match::cfg_match! {
            target_arch = "x86_64" => (
                cfg_match::cfg_match! {
                    target_feature = "rdseed" => unsafe {core::arch::x86_64::_rdseed64_step(&mut val)},
                    target_feature = "rdrand" => unsafe {core::arch::x86_64::_rdrand64_step(&mut val)},
                    _ => unreachable!()
                }
            ),
            target_arch = "x86" => (
                cfg_match::cfg_match! {
                    target_feature = "rdseed" => unsafe {core::arch::x86::_rdseed32_step(&mut val)},
                    target_feature = "rdrand" => unsafe {core::arch::x86::_rdrand32_step(&mut val)},
                    _ => unreachable!()
                }
            )
        }) != 1
        {}
        val as usize
    }
}

#[cfg(any(
    target_feature = "rdseed",
    all(
        target_feature = "rdrand",
        feature = "use-insecure-hw-rng",
        lc_crypto_insecure_rng
    )
))]
impl CsRand for X86Rand {
    fn next_bytes(&mut self, bytes: &mut [u8]) -> lc_crypto_primitives::error::Result<()> {
        let mut chunks = bytes.array_chunks_mut();
        for chunk in &mut chunks {
            *chunk = self.poll_word().to_ne_bytes();
        }

        let rem = chunks.into_remainder();

        if !rem.is_empty() {
            let val = self.poll_word().to_ne_bytes();
            let len = rem.len();

            rem.copy_from_slice(&val[..len]);
        }

        Ok(())
    }
}
