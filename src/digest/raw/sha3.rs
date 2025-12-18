mod private {
    use core::ops::{BitAnd, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, ShlAssign};

    use crate::traits::{ByteArray, SecretTy};
    use bytemuck::Pod;

    pub trait Sha3Word:
        BitAnd<Output = Self>
        + BitXor<Output = Self>
        + Not<Output = Self>
        + BitOr<Output = Self>
        + BitXorAssign
        + BitOrAssign
        + Shl<u32, Output = Self>
        + ShlAssign<u32>
        + SecretTy
        + Pod
        + Sized
    {
        type FromBytes: ByteArray;

        type StateBytes: ByteArray;

        const BITS: u32;

        const L: u32;

        const BYTES: usize;

        fn from_le_bytes(bytes: Self::FromBytes) -> Self;
        fn to_le_bytes(self) -> Self::FromBytes;

        fn from_u8(val: u8) -> Self;

        fn rotate_left(self, n: u32) -> Self;
    }

    impl Sha3Word for u64 {
        type FromBytes = [u8; 8];

        type StateBytes = [u8; 200];

        const BITS: u32 = 64;

        const L: u32 = 6;

        const BYTES: usize = 8;

        fn from_le_bytes(bytes: Self::FromBytes) -> Self {
            u64::from_le_bytes(bytes)
        }

        fn to_le_bytes(self) -> Self::FromBytes {
            self.to_le_bytes()
        }

        fn from_u8(val: u8) -> Self {
            val as Self
        }

        fn rotate_left(self, n: u32) -> Self {
            self.rotate_left(n)
        }
    }

    impl Sha3Word for u32 {
        type FromBytes = [u8; 4];

        type StateBytes = [u8; 100];

        const BITS: u32 = 32;

        const L: u32 = 5;

        const BYTES: usize = 4;

        fn from_le_bytes(bytes: Self::FromBytes) -> Self {
            Self::from_le_bytes(bytes)
        }

        fn to_le_bytes(self) -> Self::FromBytes {
            self.to_le_bytes()
        }

        fn from_u8(val: u8) -> Self {
            val as Self
        }

        fn rotate_left(self, n: u32) -> Self {
            self.rotate_left(n)
        }
    }
}

use core::marker::PhantomData;

use crate::{
    array::BaseArrayVec,
    digest::{ContinuousOutputDigest, RawDigest, ResetableDigest},
    mem::explicit_zero_in_place,
    traits::ByteArray,
};
use private::Sha3Word;

use crate::digest::SecretDigest;

pub trait KeccackSpec {
    type Word: Sha3Word;

    type Output: ByteArray;
    type Rate: ByteArray;

    const OUT_BITS: u32;

    const ROUNDS: u32;

    const PREPAD_BITS: u8;
    const PREPAD_LENGTH: u32;
}

pub struct Keccack<S: KeccackSpec>([[S::Word; 5]; 5]);

impl<S: KeccackSpec> Default for Keccack<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: KeccackSpec> Keccack<S> {
    pub const fn new() -> Self {
        const {
            assert!((S::OUT_BITS as usize + 7) / 8 == S::Output::LEN);
            assert!(S::Rate::LEN * 8 <= (S::Word::BITS * 25) as usize);
            assert!(S::Rate::LEN != 0);
        }
        Self(bytemuck::zeroed())
    }

    fn permute_state(&mut self) {
        let mut state = self.0;
        for r in 0..S::ROUNDS {
            state = permute_round(state, r);
        }
        self.0 = state;
    }

    pub fn raw_output(&mut self) -> S::Rate {
        let mut r = bytemuck::zeroed::<S::Rate>();
        let mut window = r.as_mut();
        for i in 0..5 {
            for j in 0..5 {
                let w = self.0[i][j];
                let bytes = w.to_le_bytes();
                let l = window.len().min(S::Word::BYTES);
                let left;
                (left, window) = window.split_at_mut(l);
                left.copy_from_slice(&bytes.as_ref()[..l]);
                if window.is_empty() {
                    self.permute_state();

                    return r;
                }
            }
        }

        unreachable!()
    }
}

fn permute_round<W: Sha3Word>(arr: [[W; 5]; 5], r: u32) -> [[W; 5]; 5] {
    permute_iota(permute_chi(permute_pi(permute_rho(permute_theta(arr)))), r)
}

fn permute_theta<W: Sha3Word>(arr: [[W; 5]; 5]) -> [[W; 5]; 5] {
    let mut ret = arr;

    for j in 0..5 {
        let p = arr
            .iter()
            .map(|v| v[(j + 4) % 5] & v[(j + 1) % 5].rotate_left(1))
            .fold(bytemuck::zeroed::<W>(), |a, b| a ^ b);
        for i in 0..5 {
            ret[i][j] ^= p;
        }
    }

    ret
}

fn permute_pi<W: Sha3Word>(arr: [[W; 5]; 5]) -> [[W; 5]; 5] {
    let mut ret: [[W; 5]; 5] = bytemuck::zeroed();
    for i in 0..5 {
        for j in 0..5 {
            ret[(3 * i + 2 * j) % 5][i] = arr[i][j];
        }
    }
    ret
}

fn permute_chi<W: Sha3Word>(arr: [[W; 5]; 5]) -> [[W; 5]; 5] {
    let mut ret = arr;

    for i in 0..5 {
        for j in 0..5 {
            ret[i][j] ^= !ret[i][(j + 1) % 5] & ret[i][(j + 2) % 5];
        }
    }
    ret
}

/*

0 1 190 28 91
36 300 6 55 276
3 10 171 153 231
105 45 15 21 136
210 66 253 120 78
*/

#[rustfmt::skip]
const TBL: [[u32; 5]; 5] = [
    [0  , 36 , 3  , 105, 210],
    [1  , 300, 10 , 45 , 66 ],
    [190, 6  , 171, 15 , 253],
    [28 , 55 , 153, 21 , 120],
    [91 , 276, 231, 136, 78 ],
];

fn permute_rho<W: Sha3Word>(arr: [[W; 5]; 5]) -> [[W; 5]; 5] {
    let mut res = arr;
    for i in 0..5 {
        for j in 0..5 {
            res[i][j] = arr[i][j].rotate_left(TBL[i][j] & (W::BITS - 1));
        }
    }
    res
}

#[inline]
fn update_lfsr(mut n: u8) -> u8 {
    let b = n >> 7;
    n <<= 1;
    n ^= b | b << 4 | b << 5 | b << 6;
    n
}

fn rc_word<W: Sha3Word>(n: u32) -> W {
    let mut word = bytemuck::zeroed::<W>();
    let mut lfsr = 1;
    let mut r = (7 * n) % 255;
    for _ in 0..r {
        lfsr = update_lfsr(lfsr);
    }
    for i in 0..=W::L {
        let n = (1u32 << i) - 1;
        word |= W::from_u8(lfsr & 1) << n;
        r += 1;
        if r == 255 {
            lfsr = 1;
            r = 0;
        } else {
            lfsr = update_lfsr(lfsr);
        }
    }
    word
}

fn permute_iota<W: Sha3Word>(mut arr: [[W; 5]; 5], r: u32) -> [[W; 5]; 5] {
    arr[0][0] ^= rc_word(r);
    arr
}

type Word<S> = <S as KeccackSpec>::Word;
type StateBytes<S> = <Word<S> as Sha3Word>::StateBytes;

fn pad_sha3<S: KeccackSpec>(rest: &[u8]) -> S::Rate {
    const {
        assert!(S::PREPAD_LENGTH < 7);
    }
    let mut block = BaseArrayVec::<S::Rate>::from_slice(rest);
    block.push(S::PREPAD_BITS | (1u8.unbounded_shl(S::PREPAD_LENGTH)));
    let mut block = block.into_inner();
    *block.last_mut() |= 0x80;
    block
}

impl<S: KeccackSpec> RawDigest for Keccack<S> {
    type Block = S::Rate;

    type Output = S::Output;

    fn raw_update(&mut self, block: &Self::Block) -> crate::error::Result<()> {
        let arr = BaseArrayVec::<<Word<S> as Sha3Word>::StateBytes>::from_slice(block);
        let sl: [[<Word<S> as Sha3Word>::FromBytes; 5]; 5] = bytemuck::must_cast(arr.into_inner());

        for i in 0..5 {
            for j in 0..5 {
                self.0[i][j] ^= <Word<S> as Sha3Word>::from_le_bytes(sl[i][j]);
            }
        }

        self.permute_state();
        Ok(())
    }

    fn raw_update_final(&mut self, rest: &[u8]) -> crate::error::Result<()> {
        let block = pad_sha3::<S>(rest);
        self.raw_update(&block)
    }

    fn finish(&mut self) -> crate::error::Result<Self::Output> {
        let mut output = bytemuck::zeroed::<Self::Output>();

        let lmask = const { 0xFFu8 >> ((8 - (S::OUT_BITS & 7)) & 7) };

        let mut output_sl = output.as_mut();

        let mut arr_chunks = S::Rate::array_chunks_mut(&mut output_sl);

        for chunk in &mut arr_chunks {
            let bytes = self.raw_output();
            chunk.as_mut().copy_from_slice(bytes.as_ref());
        }

        let rem = arr_chunks.into_remainder();

        let rlen = rem.len();

        if rlen > 0 {
            let bytes = self.raw_output();
            rem.copy_from_slice(&bytes.as_ref()[..rlen]);
        }

        *output.last_mut() &= lmask;

        Ok(output)
    }
}

impl<S: KeccackSpec> ContinuousOutputDigest for Keccack<S> {}

impl<S: KeccackSpec> ResetableDigest for Keccack<S> {
    fn reset(&mut self) -> crate::error::Result<()> {
        explicit_zero_in_place(&mut self.0);
        Ok(())
    }
}

impl<S: KeccackSpec> SecretDigest for Keccack<S> {}

macro_rules! sha3 {
    {
        $spec_name:ident ($output_len:literal)
    } => {
        const _: () = {assert!($output_len%8 == 0);};
        pub struct $spec_name (());
        impl KeccackSpec for $spec_name {
            type Word = u64;

            type Output = [u8; $output_len/8];
            type Rate = [u8; (1600 - 2*$output_len)/8];

            const OUT_BITS: u32 = $output_len;

            const ROUNDS: u32 = 24;

            const PREPAD_BITS: u8 = 0b10;
            const PREPAD_LENGTH: u32 = 2;
        }
    };
}

sha3!(Sha3Spec224(224));
sha3!(Sha3Spec256(256));

sha3!(Sha3Spec384(384));

sha3!(Sha3Spec512(512));

pub type Sha3_224 = Keccack<Sha3Spec224>;

pub type Sha3_256 = Keccack<Sha3Spec256>;

pub type Sha3_384 = Keccack<Sha3Spec384>;

pub type Sha3_512 = Keccack<Sha3Spec512>;

macro_rules! shake_impl {
    {
        $spec_name:ident ($capacity:literal) = $pad:literal
    } => {
        const _: () = {assert!($capacity%8 == 0);};
        pub struct $spec_name <__O, const __OUT_BITS: u32>(PhantomData::<__O>);
        impl<__O: ByteArray, const __OUT_BITS: u32> KeccackSpec for $spec_name <__O, __OUT_BITS> {
            type Word = u64;

            type Output = __O;
            type Rate = [u8; (1600 - $capacity)/8];

            const OUT_BITS: u32 = __OUT_BITS;

            const ROUNDS: u32 = 24;

            const PREPAD_BITS: u8 = $pad;
            const PREPAD_LENGTH: u32 = Self::PREPAD_BITS.count_zeros();
        }
    };
}

shake_impl!(RawShake128Spec(256) = 0b11);
shake_impl!(RawShake256Spec(512) = 0b11);

shake_impl!(Shake128Spec(256) = 0b1111);
shake_impl!(Shake256Spec(512) = 0b1111);

#[macro_export]
macro_rules! shake128 {
    ($bits:expr) => {
        $crate::digest::raw::sha3::Keccack::<
            $crate::digest::raw::sha3::Shake128Spec<[u8; (($bits + 7) / 8)], $bits>,
        >
    };
}

#[macro_export]
macro_rules! shake256 {
    ($bits:expr) => {
        $crate::digest::raw::sha3::Keccack::<
            $crate::digest::raw::sha3::Shake256Spec<[u8; (($bits + 7) / 8)], $bits>,
        >
    };
}

#[macro_export]
macro_rules! raw_shake128 {
    ($bits:expr) => {
        $crate::digest::raw::sha3::Keccack::<
            $crate::digest::raw::sha3::RawShake128Spec<[u8; (($bits + 7) / 8)], $bits>,
        >
    };
}

#[macro_export]
macro_rules! raw_shake256 {
    ($bits:expr) => {
        $crate::digest::raw::sha3::Keccack::<
            $crate::digest::raw::sha3::RawShake256Spec<[u8; (($bits + 7) / 8)], $bits>,
        >
    };
}

#[cfg(test)]
mod test {
    use crate::{
        digest::raw::sha3::{KeccackSpec, private::Sha3Word},
        traits::ByteArray,
    };

    const fn with_prefix_first_last<const N: usize>(
        prefix: impl ByteArray,
        first: u8,
        last: u8,
    ) -> [u8; N] {
        const fn with_prefix_first_last_impl<const N: usize, P: ByteArray>(
            prefix: P,
            first: u8,
            last: u8,
        ) -> [u8; N] {
            const {
                assert!((N - P::LEN) > 1);
            }
            let mut arr = bytemuck::zeroed::<[u8; N]>();
            let (begin, end) = arr.split_at_mut(P::LEN);
            begin.copy_from_slice(crate::mem::as_slice(&prefix));
            match end {
                [begin, .., end] => {
                    *begin = first;
                    *end = last;
                }
                _ => unreachable!(),
            }

            arr
        }
        with_prefix_first_last_impl(prefix, first, last)
    }
    macro_rules! test_permute{
        ($($(#[$meta:meta])* $func:ident => [$($input:tt $(($($extra_params:expr),* $(,)?))? => $output:expr),* $(,)?]),* $(,)?) => {
            $($(#[$meta])*
            #[test]
            fn ${concat(test_, $func)}() {
                $({
                    let __input = const { $input };
                    let __expected = const { $output } ;
                    let __actual = super::$func(__input $(, $(const { $extra_params }),*)?);
                    assert_eq!(__expected, __actual, "input: {__input:x?} -> expected: {__expected:x?}, actual: {__actual:x?}");
                })*
            })*
        };
    }

    test_permute! {
        permute_theta => [
            [[0u64;5];5] => [[0u64;5];5],
            [[!0u64;5];5] => [[0u64;5];5],
        ],
        permute_rho => [
            [[0u64;5];5] => [[0u64;5];5],
            [[!0u64;5];5] => [[!0u64;5];5],
        ],
        permute_pi => [
            [[0u64;5];5] => [[0u64;5];5],
            [[!0u64;5];5] => [[!0u64;5];5],
            [[0u64,1,2,3,4], [5,6,7,8,9], [10, 11, 12, 13, 14], [15, 16,17,18,19,], [20, 21, 22, 23, 24]] => [
                [0u64, 6, 12, 18, 24],
                [3, 9, 10, 16, 22],
                [1, 7, 13, 19, 20],
                [4, 5, 11, 17, 23],
                [2, 8, 14, 15, 21],
            ]
        ],
        permute_chi => [
            [[0u64;5];5] => [[0u64;5];5],
            [[!0u64;5];5] => [[!0u64;5];5]
        ],
        permute_iota  => [
            [[0u64;5];5] (0) => [
                [1u64, 0, 0, 0, 0],
                [0u64;5],
                [0u64;5],
                [0u64;5],
                [0u64;5],
            ],
            [[0u64;5];5] (1) => [
                [0x8082u64, 0,0,0,0],
                [0u64; 5],
                [0u64; 5],
                [0u64; 5],
                [0u64; 5],
            ],
            [[!0u64;5];5] (0) => [
                [!1u64, !0, !0, !0, !0],
                [!0u64;5],
                [!0u64;5],
                [!0u64;5],
                [!0u64;5],
            ],
        ],
        permute_round => [
            [[0u64;5];5] (0) => [
                [1u64, 0, 0, 0, 0],
                [0u64;5],
                [0u64;5],
                [0u64;5],
                [0u64;5],
            ],
        ],
    }

    fn test_round_impl<S: KeccackSpec>() {
        const { assert!(S::ROUNDS == <S::Word as Sha3Word>::L * 2 + 12) }
    }

    #[test]
    fn test_round() {
        test_round_impl::<super::Sha3Spec224>();
        test_round_impl::<super::Sha3Spec256>();
        test_round_impl::<super::Sha3Spec384>();
        test_round_impl::<super::Sha3Spec512>();
        test_round_impl::<super::Shake128Spec<[u8; 32], 256>>();
        test_round_impl::<super::Shake256Spec<[u8; 32], 256>>();
    }
}
