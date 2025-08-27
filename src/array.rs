use core::{
    borrow::{Borrow, BorrowMut},
    cmp::Ordering,
    hash::Hash,
    ops::{Deref, DerefMut, Index, IndexMut},
    slice::SliceIndex,
};

use bytemuck::Zeroable;

use crate::traits::ByteArray;

pub unsafe trait ByteSliceableOutput<I: SliceIndex<[u8]>> {
    type Output: ?Sized + 'static;

    fn wrap(sl: &I::Output) -> &Self::Output;
    fn wrap_mut(sl: &mut I::Output) -> &mut Self::Output;
}

pub unsafe trait ByteSliceable: Eq {
    fn len(&self) -> usize;

    fn get<I: SliceIndex<[u8]>>(&self, idx: I) -> Option<&Self::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;
    fn index<I: SliceIndex<[u8]>>(&self, idx: I) -> &Self::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;
    unsafe fn get_unchecked<I: SliceIndex<[u8]>>(&self, idx: I) -> &Self::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;

    fn get_mut<I: SliceIndex<[u8]>>(&mut self, idx: I) -> Option<&mut Self::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;
    fn index_mut<I: SliceIndex<[u8]>>(&mut self, idx: I) -> &mut Self::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;
    unsafe fn get_unchecked_mut<I: SliceIndex<[u8]>>(&mut self, idx: I) -> &mut Self::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static;

    unsafe fn slice_unchecked(&self, idx: impl SliceIndex<[u8], Output = [u8]>) -> &Self;

    unsafe fn slice_unchecked_mut(
        &mut self,
        idx: impl SliceIndex<[u8], Output = [u8]>,
    ) -> &mut Self;

    fn copy_from_slice(&mut self, other: &Self);

    fn write_zeroes(&mut self);
}

unsafe impl<I: SliceIndex<[u8]>> ByteSliceableOutput<I> for [u8]
where
    I::Output: 'static,
{
    type Output = I::Output;

    fn wrap(sl: &I::Output) -> &Self::Output {
        sl
    }

    fn wrap_mut(sl: &mut I::Output) -> &mut Self::Output {
        sl
    }
}

unsafe impl ByteSliceable for [u8] {
    fn len(&self) -> usize {
        self.len()
    }

    fn get<I: SliceIndex<[u8]>>(&self, idx: I) -> Option<&<Self as ByteSliceableOutput<I>>::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        self.get(idx).map(Self::wrap)
    }
    fn index<I: SliceIndex<[u8]>>(&self, idx: I) -> &<Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap(&self[idx])
    }
    unsafe fn get_unchecked<I: SliceIndex<[u8]>>(
        &self,
        idx: I,
    ) -> &<Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap(unsafe { self.get_unchecked(idx) })
    }

    fn get_mut<I: SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> Option<&mut <Self as ByteSliceableOutput<I>>::Output>
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        self.get_mut(idx).map(Self::wrap_mut)
    }
    fn index_mut<I: SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> &mut <Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap_mut(&mut self[idx])
    }
    unsafe fn get_unchecked_mut<I: SliceIndex<[u8]>>(
        &mut self,
        idx: I,
    ) -> &mut <Self as ByteSliceableOutput<I>>::Output
    where
        Self: ByteSliceableOutput<I>,
        I::Output: 'static,
    {
        Self::wrap_mut(unsafe { self.get_unchecked_mut(idx) })
    }

    unsafe fn slice_unchecked(&self, idx: impl SliceIndex<[u8], Output = [u8]>) -> &Self {
        unsafe { self.get_unchecked(idx) }
    }

    unsafe fn slice_unchecked_mut(
        &mut self,
        idx: impl SliceIndex<[u8], Output = [u8]>,
    ) -> &mut Self {
        unsafe { self.get_unchecked_mut(idx) }
    }

    fn copy_from_slice(&mut self, other: &Self) {
        self.copy_from_slice(other);
    }

    fn write_zeroes(&mut self) {
        self.fill(0);
    }
}

pub unsafe trait ArrayVecArray: Zeroable + Eq {
    type Underlying: ByteArray;
    type Slice: ByteSliceable + ?Sized;

    const LEN: usize;

    fn as_slice(&self) -> &Self::Slice;

    fn as_slice_mut(&mut self) -> &mut Self::Slice;

    fn insert_at(&mut self, idx: usize, b: u8);

    fn from_underlying(underlying: Self::Underlying) -> Self;

    fn cmp_slice(a: &Self::Slice, b: &Self::Slice) -> Ordering
    where
        Self: Ord;

    fn hash_slice<H: core::hash::Hasher>(a: &Self::Slice, hasher: &mut H)
    where
        Self: Hash;
}

unsafe impl<A: ByteArray> ArrayVecArray for A {
    type Slice = [u8];
    type Underlying = A;
    const LEN: usize = A::LEN;
    fn as_slice(&self) -> &Self::Slice {
        self.as_ref()
    }

    fn as_slice_mut(&mut self) -> &mut Self::Slice {
        self.as_mut()
    }

    fn cmp_slice(a: &Self::Slice, b: &Self::Slice) -> Ordering {
        a.cmp(b)
    }

    fn hash_slice<H: core::hash::Hasher>(a: &Self::Slice, hasher: &mut H) {
        a.hash(hasher);
    }

    fn insert_at(&mut self, idx: usize, b: u8) {
        self.as_slice_mut()[idx] = b;
    }

    fn from_underlying(underlying: Self::Underlying) -> Self {
        underlying
    }
}

#[derive(Copy, Clone)]
pub struct BaseArrayVec<A> {
    inner: A,
    len: usize,
}

impl<A: ArrayVecArray> Default for BaseArrayVec<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: ArrayVecArray> PartialEq for BaseArrayVec<A> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<A: ArrayVecArray> Eq for BaseArrayVec<A> {}

impl<A: ArrayVecArray + Hash> Hash for BaseArrayVec<A> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        <A as ArrayVecArray>::hash_slice(self.as_slice(), state);
    }
}

impl<A: ArrayVecArray + Ord> PartialOrd for BaseArrayVec<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(A::cmp_slice(self.as_slice(), other.as_slice()))
    }
}

impl<A: ArrayVecArray + Ord> Ord for BaseArrayVec<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        A::cmp_slice(self.as_slice(), other.as_slice())
    }
}

impl<A: ArrayVecArray> core::fmt::Debug for BaseArrayVec<A>
where
    A::Slice: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<A: ArrayVecArray> BaseArrayVec<A> {
    pub const fn new() -> Self {
        Self {
            inner: bytemuck::zeroed(),
            len: 0,
        }
    }

    pub const fn new_init(arr: A) -> Self {
        Self {
            inner: arr,
            len: A::LEN,
        }
    }

    pub fn from_slice<S: AsRef<A::Slice>>(sl: S) -> Self {
        let sl = sl.as_ref();
        let mut this = Self::new();
        assert!(sl.len() <= A::LEN);
        unsafe {
            this.inner
                .as_slice_mut()
                .slice_unchecked_mut(0..sl.len())
                .copy_from_slice(sl);
        }

        this.len = sl.len();

        this
    }

    pub fn as_slice(&self) -> &A::Slice {
        unsafe { self.inner.as_slice().slice_unchecked(0..self.len) }
    }

    pub fn as_slice_mut(&mut self) -> &mut A::Slice {
        unsafe { self.inner.as_slice_mut().slice_unchecked_mut(0..self.len) }
    }

    pub fn push(&mut self, val: u8) {
        if self.len == A::LEN {
            panic!(
                "Push to Array Vec of length {} would exceed capacity",
                self.len
            );
        }

        self.inner.insert_at(self.len, val);
        self.len += 1;
    }

    pub fn extend_from_slice<S: AsRef<A::Slice> + ?Sized>(&mut self, sl: &S) {
        let sl = sl.as_ref();
        let range = self.len..(self.len + sl.len());

        if range.end > A::LEN {
            panic!(
                "Push to Array Vec of length {} would exceed capacity",
                self.len
            );
        }

        self.len = self.len + sl.len();

        unsafe {
            self.inner
                .as_slice_mut()
                .slice_unchecked_mut(range)
                .copy_from_slice(sl);
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        A::LEN
    }

    pub fn zero_pad(&mut self) {
        let start = self.len;
        unsafe {
            self.inner
                .as_slice_mut()
                .slice_unchecked_mut(start..)
                .write_zeroes()
        }
        self.len = A::LEN;
    }

    pub fn into_inner(mut self) -> A {
        self.zero_pad();

        self.inner
    }
}

impl<A: ByteArray> BaseArrayVec<A> {
    pub fn convert<B: ArrayVecArray<Underlying = A>>(self) -> BaseArrayVec<B> {
        let len = self.len;

        BaseArrayVec {
            inner: B::from_underlying(self.inner),
            len,
        }
    }
}

impl<A: ArrayVecArray> Deref for BaseArrayVec<A> {
    type Target = A::Slice;

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<A: ArrayVecArray> DerefMut for BaseArrayVec<A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

impl<A: ArrayVecArray> AsRef<A::Slice> for BaseArrayVec<A> {
    fn as_ref(&self) -> &A::Slice {
        self.as_slice()
    }
}

impl<A: ArrayVecArray> AsMut<A::Slice> for BaseArrayVec<A> {
    fn as_mut(&mut self) -> &mut A::Slice {
        self.as_slice_mut()
    }
}

impl<A: ByteArray> Borrow<[u8]> for BaseArrayVec<A> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<A: ByteArray> BorrowMut<[u8]> for BaseArrayVec<A> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<A: ArrayVecArray, I: SliceIndex<[u8]>> Index<I> for BaseArrayVec<A>
where
    A::Slice: ByteSliceableOutput<I>,
    I::Output: 'static,
{
    type Output = <A::Slice as ByteSliceableOutput<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        ByteSliceable::index(self.as_slice(), index)
    }
}

impl<A: ArrayVecArray, I: SliceIndex<[u8]>> IndexMut<I> for BaseArrayVec<A>
where
    A::Slice: ByteSliceableOutput<I>,
    I::Output: 'static,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        ByteSliceable::index_mut(self.as_slice_mut(), index)
    }
}

pub type ArrayVec<const N: usize> = BaseArrayVec<[u8; N]>;

impl<const N: usize> From<&[u8]> for ArrayVec<N> {
    fn from(value: &[u8]) -> Self {
        ArrayVec::from_slice(value)
    }
}

impl<const N: usize> From<&str> for ArrayVec<N> {
    fn from(value: &str) -> Self {
        ArrayVec::from_slice(value)
    }
}

use crate::traits::SecretTy;

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
        self.get_unchecked(idx)
    }

    unsafe fn slice_unchecked_mut(
        &mut self,
        idx: impl core::slice::SliceIndex<[u8], Output = [u8]>,
    ) -> &mut Self {
        self.get_unchecked_mut(idx)
    }

    fn copy_from_slice(&mut self, other: &Self) {
        self.copy_from_slice(other)
    }

    fn write_zeroes(&mut self) {
        self.write_zeroes();
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

    fn from_underlying(underlying: Self::Underlying) -> Self {
        Secret::new(underlying)
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
