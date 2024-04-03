//! Fowler-Noll-Vo Hashes
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

use core::ops::BitXor;
use num_traits::{AsPrimitive, WrappingMul};

/// Fowler-Noll-Vo Hashes
///
/// Both FNV-1 and FNV-1a are provided.
///
/// Note that:
/// * FNV is not a cryptographic hash.
/// * FNV is not resistant to "hash flooding" denial-of-service attacks.
pub trait Fnv: 'static + Copy + WrappingMul + BitXor<Output = Self>
where
    u8: AsPrimitive<Self>,
{
    /// The FNV prime
    const PRIME: Self;
    /// The FNV offset basis
    const OFFSET_BASIS: Self;

    /// Compute the Fowler-Noll-Vo hash FNV-1 (multiply before xor)
    fn fnv1(data: impl Iterator<Item = u8>) -> Self {
        data.fold(<Self as Fnv>::OFFSET_BASIS, |hash, byte| {
            hash.wrapping_mul(&<Self as Fnv>::PRIME) ^ byte.as_()
        })
    }

    /// Compute the Fowler-Noll-Vo hash FNV-1a (xor before multiply)
    ///
    /// ```
    /// use fnv::Fnv;
    ///
    /// /// Test vectors from
    /// /// https://datatracker.ietf.org/doc/draft-eastlake-fnv/21/
    /// for (data, h32, h64) in [
    ///     ("", 0x811c9dc5, 0xcbf29ce484222325),
    ///     ("a", 0xe40c292c, 0xaf63dc4c8601ec8c),
    ///     ("foobar", 0xbf9cf968, 0x85944171f73967e8),
    /// ] {
    ///     assert_eq!(u32::fnv1a(data.as_bytes().iter().copied()), h32);
    ///     assert_eq!(u64::fnv1a(data.as_bytes().iter().copied()), h64);
    /// }
    /// ```
    fn fnv1a(data: impl Iterator<Item = u8>) -> Self {
        data.fold(<Self as Fnv>::OFFSET_BASIS, |hash, byte| {
            (hash ^ byte.as_()).wrapping_mul(&<Self as Fnv>::PRIME)
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
