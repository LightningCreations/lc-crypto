use core::{
    borrow::{Borrow, BorrowMut},
    slice::SliceIndex,
};

use lc_crypto_primitives::{
    array::{ArrayVec, ArrayVecArray, BaseArrayVec, ByteSliceable, ByteSliceableOutput},
    traits::{ByteArray, SecretTy},
};

use crate::secret::Secret;

unsafe impl<I: SliceIndex<[u8]>> ByteSliceableOutput<I> for Secret<[u8]>
where
    I::Output: SecretTy,
    I::Output: 'static,
{
    type Output = Secret<I::Output>;

    fn wrap(sl: &I::Output) -> &Self::Output {
        Secret::from_ref(sl)
    }

    fn wrap_mut(sl: &mut I::Output) -> &mut Self::Output {
        Secret::from_mut(sl)
    }
}

unsafe impl ByteSliceable for Secret<[u8]> {
    fn len(&self) -> usize {
        self.len()
    }

    fn get<I: core::slice::SliceIndex<[u8]>>(
        &self,
        idx: I,
    ) -> Option<&<Self as ByteSliceableOutput<I>>::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        self.get_nonsecret().get(idx).map(Self::wrap)
    }

    fn index<I: core::slice::SliceIndex<[u8]>>(
        &self,
        idx: I,
    ) -> &<Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap(&self.get_nonsecret()[idx])
    }

    unsafe fn get_unchecked<I: core::slice::SliceIndex<[u8]>>(
        &self,
        idx: I,
    ) -> &<Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap(unsafe { self.get_nonsecret().get_unchecked(idx) })
    }

    fn get_mut<I: core::slice::SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> Option<&mut <Self as ByteSliceableOutput<I>>::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        self.get_mut_nonsecret().get_mut(idx).map(Self::wrap_mut)
    }

    fn index_mut<I: core::slice::SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> &mut <Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap_mut(&mut self.get_mut_nonsecret()[idx])
    }

    unsafe fn get_unchecked_mut<I: core::slice::SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> &mut <Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap_mut(unsafe { self.get_mut_nonsecret().get_unchecked_mut(idx) })
    }

    unsafe fn slice_unchecked(
        &self,
        idx: impl core::slice::SliceIndex<[u8], Output = [u8]>,
    ) -> &Self {
        todo!()
    }

    unsafe fn slice_unchecked_mut(
        &mut self,
        idx: impl core::slice::SliceIndex<[u8], Output = [u8]>,
    ) -> &mut Self {
        todo!()
    }

    fn copy_from_slice(&mut self, other: &Self) {
        todo!()
    }
}

unsafe impl<A: ByteArray> ArrayVecArray for Secret<A> {
    type Underlying = A;

    type Slice = Secret<[u8]>;

    const LEN: usize = A::LEN;

    fn as_slice(&self) -> &Self::Slice {
        self.as_byte_slice()
    }

    fn as_slice_mut(&mut self) -> &mut Self::Slice {
        self.as_byte_slice_mut()
    }

    fn insert_at(&mut self, idx: usize, b: u8) {
        self.get_mut_nonsecret().as_mut()[idx] = b;
    }

    fn cmp_slice(_: &Self::Slice, _: &Self::Slice) -> core::cmp::Ordering
    where
        Self: Ord,
    {
        const { panic!("Secret: !Ord, right") }
    }

    fn hash_slice<H: core::hash::Hasher>(_: &Self::Slice, _: &mut H)
    where
        Self: core::hash::Hash,
    {
        const { panic!("Secret: !Hash, right") }
    }
}

impl<A: ByteArray> Borrow<Secret<[u8]>> for BaseArrayVec<Secret<A>> {
    fn borrow(&self) -> &Secret<[u8]> {
        self.as_slice()
    }
}

impl<A: ByteArray> BorrowMut<Secret<[u8]>> for BaseArrayVec<Secret<A>> {
    fn borrow_mut(&mut self) -> &mut Secret<[u8]> {
        self.as_slice_mut()
    }
}

pub type SecretArrayVec<const N: usize> = BaseArrayVec<Secret<[u8; N]>>;

impl<const N: usize> From<&Secret<[u8]>> for SecretArrayVec<N> {
    fn from(value: &Secret<[u8]>) -> Self {
        Self::from_slice(value)
    }
}
