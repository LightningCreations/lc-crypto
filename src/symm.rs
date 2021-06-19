use core::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

use alloc::{boxed::Box, vec};

use zeroize::{Zeroize, Zeroizing};

pub mod aes;

pub enum Operation {
    Encrypt,
    Decrypt,
}

pub trait SymmetricCipher {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    fn init(&mut self, key: &[u8], op: Operation);
    fn update(&mut self, block: &[u8], out: &mut [u8]);
    fn do_final(&mut self, block: &[u8], out: &mut [u8]);
}

impl<C: SymmetricCipher + ?Sized> SymmetricCipher for &mut C {
    const BLOCK_SIZE: usize = C::BLOCK_SIZE;
    const KEY_SIZE: usize = C::KEY_SIZE;
    fn init(&mut self, key: &[u8], op: Operation) {
        <C as SymmetricCipher>::init(self, key, op)
    }
    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        <C as SymmetricCipher>::update(self, block, out)
    }
    fn do_final(&mut self, block: &[u8], out: &mut [u8]) {
        <C as SymmetricCipher>::update(self, block, out)
    }
}

impl<C: SymmetricCipher + ?Sized> SymmetricCipher for Box<C> {
    const BLOCK_SIZE: usize = C::BLOCK_SIZE;
    const KEY_SIZE: usize = C::KEY_SIZE;
    fn init(&mut self, key: &[u8], op: Operation) {
        <C as SymmetricCipher>::init(self, key, op)
    }
    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        <C as SymmetricCipher>::update(self, block, out)
    }
    fn do_final(&mut self, block: &[u8], out: &mut [u8]) {
        <C as SymmetricCipher>::update(self, block, out)
    }
}

pub struct CBC<C> {
    cipher: C,
    iv: Box<[u8]>,
}

impl<C: Zeroize> Zeroize for CBC<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.iv.zeroize();
    }
}

impl<C> Drop for CBC<C> {
    fn drop(&mut self) {
        self.iv.zeroize(); // Can't Zeroize cipher, just have to hope that it will
    }
}

impl<C> CBC<C> {
    pub fn new(cipher: C, iv: Box<[u8]>) -> Self {
        Self { cipher, iv }
    }

    pub fn into_inner(self) -> C {
        let mut md = ManuallyDrop::new(self);
        let ret = unsafe { core::ptr::addr_of_mut!(md.cipher).read() };
        md.iv.zeroize();
        ret
    }

    pub fn get_iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<C: SymmetricCipher> SymmetricCipher for CBC<C> {
    const BLOCK_SIZE: usize = C::BLOCK_SIZE;

    const KEY_SIZE: usize = C::KEY_SIZE;

    fn init(&mut self, key: &[u8], op: Operation) {
        self.cipher.init(key, op)
    }

    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        let mut bytes = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
        bytes.copy_from_slice(block);
        for i in 0..C::BLOCK_SIZE {
            (*bytes)[i] ^= self.iv[i];
        }
        self.cipher.update(&bytes, out);
        self.iv.copy_from_slice(out);
    }

    fn do_final(&mut self, block: &[u8], out: &mut [u8]) {
        let mut bytes = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
        bytes.copy_from_slice(block);
        for i in 0..C::BLOCK_SIZE {
            (*bytes)[i] ^= self.iv[i];
        }
        self.cipher.do_final(&bytes, out);
        self.iv.copy_from_slice(out);
    }
}

impl<C> Deref for CBC<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.cipher
    }
}

impl<C> DerefMut for CBC<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.cipher
    }
}

#[derive(Default)]
pub struct Pkcs5Pad<C>(C);

impl<C> Pkcs5Pad<C> {
    pub fn new(cipher: C) -> Self {
        Self(cipher)
    }
    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C: Zeroize> Zeroize for Pkcs5Pad<C> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<C: SymmetricCipher> SymmetricCipher for Pkcs5Pad<C> {
    const BLOCK_SIZE: usize = C::BLOCK_SIZE;

    const KEY_SIZE: usize = C::KEY_SIZE;

    fn init(&mut self, key: &[u8], op: Operation) {
        self.0.init(key, op)
    }

    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        self.0.update(block, out)
    }

    fn do_final(&mut self, mut block: &[u8], mut out: &mut [u8]) {
        if block.len() == C::BLOCK_SIZE {
            self.update(block, out);
            out = &mut out[block.len()..];
            block = &[];
        }
        let len = block.len();
        let b = (C::BLOCK_SIZE - len) as u8;
        let mut v = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
        v[..len].copy_from_slice(block);
        v[len..].fill(b);
        self.0.do_final(&v, out);
    }
}

impl<C> Deref for Pkcs5Pad<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.0
    }
}

impl<C> DerefMut for Pkcs5Pad<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.0
    }
}
