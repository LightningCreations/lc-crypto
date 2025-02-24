mod private {
    use core::iter::FusedIterator;

    pub trait Sealed {}

    pub struct ArrayChunks<'a, T: 'a, const N: usize>(
        pub(crate) core::slice::ArrayChunks<'a, T, N>,
    );

    impl<'a, T: 'a, const N: usize> Iterator for ArrayChunks<'a, T, N> {
        type Item = &'a [T; N];

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            self.0.size_hint()
        }
    }

    impl<'a, T: 'a, const N: usize> DoubleEndedIterator for ArrayChunks<'a, T, N> {
        fn next_back(&mut self) -> Option<Self::Item> {
            self.0.next_back()
        }
    }

    impl<'a, T: 'a, const N: usize> ExactSizeIterator for ArrayChunks<'a, T, N> {
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    impl<'a, T: 'a, const N: usize> FusedIterator for ArrayChunks<'a, T, N> {}
}

use core::iter::FusedIterator;

use bytemuck::Pod;
use private::{ArrayChunks, Sealed};

pub trait Remainder<'a>: 'a + Sealed {
    fn remainder(&self) -> &'a [u8];
}

impl<'a, T: 'a + Copy, const N: usize> Sealed for ArrayChunks<'a, T, N> {}

impl<'a, const N: usize> Remainder<'a> for ArrayChunks<'a, u8, N> {
    fn remainder(&self) -> &'a [u8] {
        self.0.remainder()
    }
}

pub trait ByteArray: Sealed + Pod + Eq + AsRef<[u8]> {
    const LEN: usize;
    type ArrayChunks<'a>: Iterator<Item = &'a Self>
        + ExactSizeIterator
        + DoubleEndedIterator
        + FusedIterator
        + Remainder<'a>
        + 'a
    where
        Self: 'a;

    fn array_chunks<'a>(sl: &'a [u8]) -> Self::ArrayChunks<'a>;
}

impl<const N: usize> Sealed for [u8; N] {}
impl<const N: usize> ByteArray for [u8; N] {
    const LEN: usize = N;

    type ArrayChunks<'a> = private::ArrayChunks<'a, u8, N>;

    fn array_chunks<'a>(sl: &'a [u8]) -> Self::ArrayChunks<'a> {
        const {
            assert!(N != 0);
        }
        private::ArrayChunks(sl.array_chunks())
    }
}
