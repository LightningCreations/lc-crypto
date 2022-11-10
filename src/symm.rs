use core::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

use alloc::{borrow::Cow, boxed::Box, vec, vec::Vec};

use zeroize::{Zeroize, Zeroizing};

pub mod aes;

#[derive(Copy, Clone)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

pub trait SymmetricCipher {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    fn init(&mut self, key: &[u8], op: Operation);
    fn update(&mut self, block: &[u8], out: &mut [u8]);
    fn do_final<'a>(&mut self, block: &[u8], out: &'a mut [u8]) -> Cow<'a, [u8]>;
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
    fn do_final<'a>(&mut self, block: &[u8], out: &'a mut [u8]) -> Cow<'a, [u8]> {
        <C as SymmetricCipher>::do_final(self, block, out)
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
    fn do_final<'a>(&mut self, block: &[u8], out: &'a mut [u8]) -> Cow<'a, [u8]> {
        <C as SymmetricCipher>::do_final(self, block, out)
    }
}

pub struct CBC<C> {
    cipher: C,
    iv: Box<[u8]>,
    op: Option<Operation>,
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
        Self {
            cipher,
            iv,
            op: None,
        }
    }

    #[allow(unsafe_code)]
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
        self.op = Some(op);
        self.cipher.init(key, op)
    }

    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        if let Some(Operation::Encrypt) = self.op {
            let mut bytes = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
            bytes.copy_from_slice(block);
            for i in 0..C::BLOCK_SIZE {
                (*bytes)[i] ^= self.iv[i];
            }
            self.cipher.update(&bytes, out);
            self.iv.copy_from_slice(out);
        } else {
            self.cipher.update(block, out);
            for i in 0..C::BLOCK_SIZE {
                (*out)[i] ^= self.iv[i];
            }
            self.iv.copy_from_slice(block);
        }
    }

    fn do_final<'a>(&mut self, block: &[u8], out: &'a mut [u8]) -> Cow<'a, [u8]> {
        if let Some(Operation::Encrypt) = self.op {
            let mut bytes = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
            bytes.copy_from_slice(block);
            for i in 0..C::BLOCK_SIZE {
                (*bytes)[i] ^= self.iv[i];
            }
            self.cipher.do_final(&bytes, out);
            self.iv.copy_from_slice(out);
            Cow::Borrowed(out)
        } else {
            self.cipher.do_final(block, out);
            for i in 0..C::BLOCK_SIZE {
                (*out)[i] ^= self.iv[i];
            }
            self.iv.copy_from_slice(block);
            Cow::Borrowed(out)
        }
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
pub struct Pkcs5Pad<C>(C, Option<Operation>);

impl<C> Pkcs5Pad<C> {
    pub fn new(cipher: C) -> Self {
        Self(cipher, None)
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
        self.1 = Some(op);
        self.0.init(key, op)
    }

    fn update(&mut self, block: &[u8], out: &mut [u8]) {
        self.0.update(block, out)
    }

    fn do_final<'a>(&mut self, block: &[u8], out: &'a mut [u8]) -> Cow<'a, [u8]> {
        if let Some(Operation::Encrypt) = self.1 {
            if block.len() == C::BLOCK_SIZE {
                self.update(block, out);
                let len = block.len();
                let out2 = &mut out[len..];
                let b = C::BLOCK_SIZE as u8;
                let mut v = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
                v.fill(b);
                if out2.len() < C::BLOCK_SIZE {
                    // drop(out2);
                    let mut outv = vec![0; 2 * C::BLOCK_SIZE];
                    outv.copy_from_slice(out);
                    self.0.do_final(&v, &mut outv[len..]);
                    Cow::Owned(outv)
                } else {
                    self.0.do_final(&v, out2);
                    Cow::Borrowed(out)
                }
            } else {
                let len = block.len();
                let b = (C::BLOCK_SIZE - len) as u8;
                let mut v = Zeroizing::new(vec![0u8; C::BLOCK_SIZE].into_boxed_slice());
                v[..len].copy_from_slice(block);
                v[len..].fill(b);
                self.0.do_final(&v, out)
            }
        } else {
            let ret = self.0.do_final(block, out);
            let b = *ret.last().unwrap() as usize;
            match ret {
                Cow::Borrowed(v) => Cow::Borrowed(&v[..(v.len() - b)]),
                Cow::Owned(mut v) => {
                    let len = v.len() - b;
                    v.truncate(len);
                    Cow::Owned(v)
                }
            }
        }
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

pub fn encrypt<C: SymmetricCipher>(mut cipher: C, key: &[u8], input: &[u8]) -> Vec<u8> {
    let len = input.len();
    let mut out = Vec::with_capacity(len + (C::BLOCK_SIZE - len % C::BLOCK_SIZE) % C::BLOCK_SIZE);
    let mut chunks = input.chunks(C::BLOCK_SIZE);
    let last = chunks.next_back().unwrap_or(&[]);
    cipher.init(key, Operation::Encrypt);
    for c in chunks {
        let len = out.len();
        out.resize(len + C::BLOCK_SIZE, 0);
        cipher.update(c, &mut out[len..]);
    }
    let len = out.len();
    out.resize(len + C::BLOCK_SIZE, 0);
    let sl = cipher.do_final(last, &mut out[len..]);
    if let Cow::Owned(v) = sl {
        out.extend_from_slice(&v[C::BLOCK_SIZE..]);
    }

    out
}

pub fn decrypt<C: SymmetricCipher>(mut cipher: C, key: &[u8], input: &[u8]) -> Vec<u8> {
    let len = input.len();
    let mut out = Vec::with_capacity(len + (C::BLOCK_SIZE - len % C::BLOCK_SIZE) % C::BLOCK_SIZE);
    let mut chunks = input.chunks(C::BLOCK_SIZE);
    let last = chunks.next_back().unwrap_or(&[]);
    cipher.init(key, Operation::Decrypt);
    for c in chunks {
        let len = out.len();
        out.resize(len + C::BLOCK_SIZE, 0);
        cipher.update(c, &mut out[len..]);
    }
    let len = out.len();
    out.resize(len + C::BLOCK_SIZE, 0);
    let sl = cipher.do_final(last, &mut out[len..]);
    if let Cow::Owned(v) = sl {
        out.extend_from_slice(&v[C::BLOCK_SIZE..]);
    }

    out
}
