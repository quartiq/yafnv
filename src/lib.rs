//! Fowler-Noll-Vo Hashes
//!
//! The implementation here is fully `no_std` and `no_alloc` and implements both FNV-1 and FNV-1a
//! for `u32`, `u64`, and `u128` hash sizes.
//!
//! See also the following crates:
//! * [`fnv`](https://doc.servo.org/fnv/)
//! * [`fnv-rs`](https://docs.rs/fnv_rs/latest/fnv_rs/)
//! * [`const-fnv1a-hash`](https://docs.rs/const-fnv1a-hash/latest/const_fnv1a_hash/)
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

use core::hash::{BuildHasherDefault, Hasher};
use core::ops::BitXor;
use num_traits::{AsPrimitive, WrappingMul};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

/// Fowler-Noll-Vo Hashes
///
/// Both FNV-1 and FNV-1a are provided.
///
/// Note that:
/// * FNV is not a cryptographic hash.
/// * FNV is not resistant to "hash flooding" denial-of-service attacks.
pub trait Fnv
where
    Self: 'static + Copy + WrappingMul + BitXor<Output = Self>,
    u8: AsPrimitive<Self>,
{
    /// The FNV prime
    const PRIME: Self;
    /// The FNV offset basis
    const OFFSET_BASIS: Self;

    /// Compute the Fowler-Noll-Vo hash FNV-1 (multiply before xor)
    #[inline]
    fn fnv1<I>(self, data: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        data.into_iter().fold(self, |hash, byte| {
            hash.wrapping_mul(&Self::PRIME) ^ byte.as_()
        })
    }

    /// Compute the Fowler-Noll-Vo hash FNV-1a (xor before multiply)
    ///
    /// ```
    /// use yafnv::Fnv;
    ///
    /// // Test vectors from
    /// // https://datatracker.ietf.org/doc/draft-eastlake-fnv/21/
    /// for (data, h32, h64) in [
    ///     ("", 0x811c9dc5, 0xcbf29ce484222325),
    ///     ("a", 0xe40c292c, 0xaf63dc4c8601ec8c),
    ///     ("foobar", 0xbf9cf968, 0x85944171f73967e8),
    /// ] {
    ///     let data = data.as_bytes().iter().copied();
    ///     assert_eq!(u32::OFFSET_BASIS.fnv1a(data.clone()), h32);
    ///     assert_eq!(u64::OFFSET_BASIS.fnv1a(data), h64);
    /// }
    /// ```
    #[inline]
    fn fnv1a<I>(self, data: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        data.into_iter().fold(self, |hash, byte| {
            (hash ^ byte.as_()).wrapping_mul(&Self::PRIME)
        })
    }
}

impl Fnv for u32 {
    const PRIME: u32 = 0x01000193;
    const OFFSET_BASIS: u32 = 0x811c9dc5;
}
impl Fnv for u64 {
    const PRIME: u64 = 0x00000100000001B3;
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
}
impl Fnv for u128 {
    const PRIME: u128 = 0x0000000001000000000000000000013B;
    const OFFSET_BASIS: u128 = 0x6c62272e07bb014262b821756295c58d;
}

/// Compute the FNV-1 hash.
///
/// See also [`Fnv::fnv1`].
/// Uses the default [`Fnv::OFFSET_BASIS`].
pub fn fnv1<T, I>(data: I) -> T
where
    T: Fnv,
    I: IntoIterator<Item = u8>,
    u8: AsPrimitive<T>,
{
    T::OFFSET_BASIS.fnv1(data)
}

/// Compute the FNV-1a hash.
///
/// See also [`Fnv::fnv1a`].
/// Uses the default [`Fnv::OFFSET_BASIS`].
pub fn fnv1a<T, I>(data: I) -> T
where
    T: Fnv,
    I: IntoIterator<Item = u8>,
    u8: AsPrimitive<T>,
{
    T::OFFSET_BASIS.fnv1a(data)
}

/// Fowler-Noll-Vo FNV-1a Hasher
///
/// ```
/// use core::hash::Hasher;
/// use yafnv::Fnv1aHasher;
///
/// // Test vector from https://datatracker.ietf.org/doc/draft-eastlake-fnv/21/
/// let mut h = Fnv1aHasher::default();
/// h.write("foobar".as_bytes());
/// assert_eq!(h.finish(), 0x85944171f73967e8);
/// ```
pub struct Fnv1aHasher(u64);

impl Fnv1aHasher {
    /// Create an FNV-1a hasher starting with a state corresponding
    /// to the hash `key`.
    #[inline]
    pub fn with_key(key: u64) -> Fnv1aHasher {
        Fnv1aHasher(key)
    }
}

impl Default for Fnv1aHasher {
    #[inline]
    fn default() -> Fnv1aHasher {
        Self::with_key(u64::OFFSET_BASIS)
    }
}

impl Hasher for Fnv1aHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0 = self.0.fnv1a(bytes.iter().copied());
    }
}

/// A builder for default FNV-1a hasher.
pub type Fnv1aBuildHasher = BuildHasherDefault<Fnv1aHasher>;

/// A `HashMap` using a default FNV-1a hasher.
#[cfg(feature = "std")]
pub type Fnv1aHashMap<K, V> = HashMap<K, V, Fnv1aBuildHasher>;

/// A `HashSet` using a default FNV-1a hasher.
#[cfg(feature = "std")]
pub type Fnv1aHashSet<T> = HashSet<T, Fnv1aBuildHasher>;
