use core::marker::PhantomData;

use bytemuck::{Pod, Zeroable};
use lc_crypto_primitives::{
    digest::{KeyedDigest, RawDigest, ResetableDigest},
    traits::{ByteArray, SecretTy},
};
use lc_crypto_secret::secret::Secret;

mod private {
    use core::ops::{Add, BitAnd, BitOr, BitXor, Not};

    use bytemuck::Pod;
    use lc_crypto_primitives::traits::{ByteArray, SecretTy};

    pub trait Sha2Word:
        SecretTy
        + Eq
        + Pod
        + BitAnd<Output = Self>
        + BitOr<Output = Self>
        + BitXor<Output = Self>
        + Not<Output = Self>
    {
        type FromBytes: ByteArray;
        const BITS: u32;

        type Block: ByteArray;

        type IvBytes: ByteArray;

        type MessageArray: AsRef<[Self]>
            + AsMut<[Self]>
            + IntoIterator<Item = Self, IntoIter: ExactSizeIterator>
            + Sized
            + Pod
            + Eq;

        const ROUND_CONSTANTS: Self::MessageArray;

        fn from_be_bytes(arr: Self::FromBytes) -> Self;

        fn to_be_bytes(self) -> Self::FromBytes;

        fn wrapping_add(self, other: Self) -> Self;

        /// Computes `(s0, s1)` given the input `w1=w[i-15]` and `w2=w[i-2]``
        fn sigma(w1: Self, w2: Self) -> (Self, Self);

        /// Computes `(S0, S1)` given the input `a` and `e`
        fn sum(a: Self, e: Self) -> (Self, Self);
    }

    impl Sha2Word for u32 {
        const BITS: u32 = u32::BITS;

        type Block = [u8; 64];

        type MessageArray = [u32; 64];

        type IvBytes = [u8; 32];

        const ROUND_CONSTANTS: Self::MessageArray = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        type FromBytes = [u8; 4];

        #[inline(always)]
        fn from_be_bytes(arr: Self::FromBytes) -> Self {
            Self::from_be_bytes(arr)
        }

        #[inline(always)]
        fn to_be_bytes(self) -> Self::FromBytes {
            Self::to_be_bytes(self)
        }

        #[inline(always)]
        fn sigma(w1: Self, w2: Self) -> (Self, Self) {
            let s0 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);

            (s0, s1)
        }

        #[inline(always)]
        #[allow(non_snake_case)]
        fn sum(a: Self, e: Self) -> (Self, Self) {
            let S1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

            (S0, S1)
        }

        #[inline(always)]
        fn wrapping_add(self, other: Self) -> Self {
            self.wrapping_add(other)
        }
    }

    impl Sha2Word for u64 {
        const BITS: u32 = u64::BITS;

        type Block = [u8; 128];

        type MessageArray = [u64; 80];

        type IvBytes = [u8; 64];

        const ROUND_CONSTANTS: Self::MessageArray = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];

        type FromBytes = [u8; 8];

        #[inline(always)]
        fn from_be_bytes(arr: Self::FromBytes) -> Self {
            Self::from_be_bytes(arr)
        }

        #[inline(always)]
        fn to_be_bytes(self) -> Self::FromBytes {
            Self::to_be_bytes(self)
        }

        #[inline(always)]
        fn sigma(w1: Self, w2: Self) -> (Self, Self) {
            let s0 = w1.rotate_right(1) ^ w1.rotate_right(8) ^ (w1 >> 7);
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);

            (s0, s1)
        }

        #[inline(always)]
        #[allow(non_snake_case)]
        fn sum(a: Self, e: Self) -> (Self, Self) {
            let S1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let S0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            (S0, S1)
        }
        #[inline(always)]
        fn wrapping_add(self, other: Self) -> Self {
            self.wrapping_add(other)
        }
    }

    pub trait DefaultSha2<W: Sha2Word> {
        const IV: [W; 8];
    }
}

use private::{DefaultSha2, Sha2Word};

use crate::traits::SecretDigest;

pub struct Sha2<W, const BITS: u32, O> {
    state: [W; 8],
    byte_count: u64,
    _phantom: PhantomData<fn() -> O>,
}

impl<W: Sha2Word, const BITS: u32, O: ByteArray> Sha2<W, BITS, O> {
    pub const fn new_with_iv(iv: [W; 8]) -> Self {
        const {
            assert!(BITS <= W::BITS * 8);
            assert!((BITS as usize + 7) / 8 == O::LEN);
        }
        Self {
            state: iv,
            byte_count: 0,
            _phantom: PhantomData,
        }
    }
}

macro_rules! def_new_with_iv_bytes {
    ($ty:ident) => {
        impl<const BITS: u32, O: ByteArray> Sha2<$ty, BITS, O> {
            pub const fn new_with_iv_bytes(iv: [u8; 8 * core::mem::size_of::<$ty>()]) -> Self {
                let [a, b, c, d, e, f, g, h]: [[u8; core::mem::size_of::<$ty>()]; 8] =
                    bytemuck::must_cast(iv);

                Self::new_with_iv([
                    <$ty>::from_be_bytes(a),
                    <$ty>::from_be_bytes(b),
                    <$ty>::from_be_bytes(c),
                    <$ty>::from_be_bytes(d),
                    <$ty>::from_be_bytes(e),
                    <$ty>::from_be_bytes(f),
                    <$ty>::from_be_bytes(g),
                    <$ty>::from_be_bytes(h),
                ])
            }
        }

        impl<const BITS: u32, O: ByteArray> KeyedDigest for Sha2<$ty, BITS, O> {
            type Key = [u8; 8 * core::mem::size_of::<$ty>()];

            fn reset_with_key(
                &mut self,
                key: &Self::Key,
            ) -> lc_crypto_primitives::error::Result<()> {
                *self = Self::new_with_iv_bytes(*key);
                Ok(())
            }
        }
    };
}

def_new_with_iv_bytes!(u32);
def_new_with_iv_bytes!(u64);

impl<W: Sha2Word, const BITS: u32, O: ByteArray> RawDigest for Sha2<W, BITS, O> {
    type Block = W::Block;

    type Output = O;

    fn raw_update(&mut self, block: &Self::Block) -> lc_crypto_primitives::error::Result<()> {
        self.byte_count += Self::Block::LEN as u64;
        let mut w: [W; 16] = bytemuck::zeroed();

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for (i, &x) in W::FromBytes::array_chunks(block.as_ref()).enumerate() {
            w[i] = W::from_be_bytes(x);
        }

        // Perform both the message expansion step, and the compression step interleaved
        // Note that this will expand an additional 16 times but those expansions won't be used.
        // At the `i`th round, we compute `w[i+16]`, having `w[i..(i+16)]` already calcuated
        // Because future rounds never reference past rounds, other than to populate the message array,
        // We can safely overwrite the space `w[i]` in the working array, thus using at most 16 total words of memory
        for (i, k) in W::ROUND_CONSTANTS.into_iter().enumerate() {
            #[allow(non_snake_case)]
            let (S0, S1) = W::sum(a, e);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(S1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(w[i & 15]);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = S0.wrapping_add(maj);

            let (s0, s1) = W::sigma(w[(i + 1) & 15], w[(i + 14) & 15]);
            w[i & 15] = w[i & 15]
                .wrapping_add(s0)
                .wrapping_add(w[(i + 9) & 15])
                .wrapping_add(s1);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (a, b) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *a = (*a).wrapping_add(b);
        }
        Ok(())
    }

    fn raw_update_final(&mut self, rest: &[u8]) -> lc_crypto_primitives::error::Result<()> {
        let final_size = const { Self::Block::LEN - (2 * size_of::<W>() + 1) };
        let bitcount = (self.byte_count + rest.len() as u64) << 3;

        let mut fblock = if rest.len() < final_size {
            let mut fblock = Self::Block::extend(rest);

            fblock.as_mut()[rest.len()] = 0x80;
            fblock
        } else {
            let mut iblock: W::Block = Self::Block::extend(rest);
            if rest.len() < Self::Block::LEN {
                iblock.as_mut()[rest.len()] = 0x80;
                self.raw_update(&iblock)?;
                bytemuck::zeroed()
            } else {
                let mut fblock: W::Block = bytemuck::zeroed();
                fblock.as_mut()[0] = 0x80;
                fblock
            }
        };

        *fblock.last_chunk_mut() = bitcount.to_be_bytes();

        self.raw_update(&fblock)
    }

    fn finish(&self) -> lc_crypto_primitives::error::Result<Self::Output> {
        let raw_array = self.state.map(|v| v.to_be_bytes());
        let mut output: O = O::truncate(bytemuck::bytes_of(&raw_array));
        let tbits = (O::LEN as u32 * 8) - BITS;
        let n = (0xFF) >> tbits;
        *output.last_mut() &= n;

        Ok(output)
    }
}

impl<W: Sha2Word, const BITS: u32, O: ByteArray> SecretDigest for Sha2<W, BITS, O> {}

impl<W: Sha2Word, const BITS: u32, O: ByteArray> Sha2<W, BITS, O>
where
    Self: DefaultSha2<W>,
{
    pub const fn new() -> Self {
        Self::new_with_iv(Self::IV)
    }
}

impl<W: Sha2Word, const BITS: u32, O: ByteArray> ResetableDigest for Sha2<W, BITS, O>
where
    Self: DefaultSha2<W>,
{
    fn reset(&mut self) -> lc_crypto_primitives::error::Result<()> {
        *self = Self::new();
        Ok(())
    }
}

impl DefaultSha2<u32> for Sha2<u32, 256, [u8; 32]> {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
}

impl DefaultSha2<u32> for Sha2<u32, 224, [u8; 28]> {
    const IV: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
}

impl DefaultSha2<u64> for Sha2<u64, 512, [u8; 64]> {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
}

impl DefaultSha2<u64> for Sha2<u64, 384, [u8; 48]> {
    const IV: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];
}

impl DefaultSha2<u64> for Sha2<u64, 256, [u8; 32]> {
    const IV: [u64; 8] = [
        0x22312194fc2bf72c,
        0x9f555fa3c84c64c2,
        0x2393b86b6f53b151,
        0x963877195940eabd,
        0x96283ee2a88effe3,
        0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa,
        0x0eb72ddC81c52ca2,
    ];
}

impl DefaultSha2<u64> for Sha2<u64, 224, [u8; 28]> {
    const IV: [u64; 8] = [
        0x8c3d37c819544da2,
        0x73e1996689dcd4d6,
        0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf,
        0x0f6d2b697bd44da8,
        0x77e36f7304C48942,
        0x3f9d85a86a1d36C8,
        0x1112e6ad91d692a1,
    ];
}

impl Sha2<u64, 512, [u8; 64]> {
    pub const fn new_modified() -> Self {
        Self::new_with_iv([
            0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5,
            0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5,
            0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5,
            0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5,
            0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5,
            0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5,
            0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5,
            0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5,
        ])
    }
}

pub type Sha512 = Sha2<u64, 512, [u8; 64]>;
pub type Sha384 = Sha2<u64, 384, [u8; 48]>;
pub type Sha256 = Sha2<u32, 256, [u8; 32]>;
pub type Sha224 = Sha2<u32, 224, [u8; 28]>;

pub type Sha512_256 = Sha2<u64, 256, [u8; 32]>;
pub type Sha512_224 = Sha2<u64, 224, [u8; 28]>;

impl<const N: u32, O: ByteArray> Sha2<u64, N, O> {
    pub fn new_512_t() -> Self {
        const { assert!(N < 512 && N != 384 && N > 0) }
        let mut modified = Sha512::new_modified();
        let mut buf = *b"SHA-512/\0\0\0";
        let n0 = (N % 10) as u8 + 0x30;
        let n1 = ((N / 10) % 10) as u8 + 0x30;
        let n2 = ((N / 10) % 10) as u8 + 0x30;
        let mut len = 8;

        for (a, b) in buf[8..]
            .iter_mut()
            .zip([n2, n1, n0].into_iter().skip_while(|v| (*v) != 0))
        {
            *a = b;
            len += 1;
        }
        modified.raw_update_final(&buf[..len]).unwrap();
        Self::new_with_iv_bytes(modified.finish().unwrap())
    }
}

#[macro_export]
macro_rules! sha512_t {
    ($bits:expr) => {
        $crate::raw::sha2::Sha2::<u64, { $bits }, [u8; (const { ($bits + 7) / 8 })]>
    };
}
