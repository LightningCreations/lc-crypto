#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64;

use zeroize::Zeroizing;

use core::convert::TryInto;

#[target_feature(enable="sha",enable="sse3")]
pub unsafe fn sha1_update_x86_64(block: &[u8],h: &mut [u32;8]){
    let mut m = [unsafe{x86_64::_mm_setzero_si128()};20];
    let block: Zeroizing<[[[u8; 4];4]; 4]> = Zeroizing::new(
        bytemuck::cast_slice::<u8, [[u8; 4];4]>(block)
            .try_into()
            .unwrap(),
    );

    for i in 0..4 {
        let mut words = [0u32;4];
        for j in 0..4{
            words[j] = u32::from_be_bytes(block[i][j]);
        }
        m[i] = unsafe{core::mem::transmute(words)};
    }
}