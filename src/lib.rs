//! Fowler-Noll-Vo Hashes
//!
//! Both FNV-1 and FNV-1a are implemented for `u32`, `u64`, and `u128`.
//!
//! FNV is not a cryptographic hash.
//!
//! FNV is not resistant to "hash flooding" denial-of-service attacks.
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

use paste::paste;

macro_rules! fnv_impl {
    ($ty:ty, $size:literal, $prime:literal, $offset:literal) => {
        paste! {
            /// Compute the Fowler-Noll-Vo hash FNV-1 of a slice.
            pub fn [<fnv1_ $size>](data: &[u8]) -> $ty {
                data.iter().fold($offset, |hash, byte| hash.wrapping_mul($prime) ^ *byte as $ty)
            }

            /// Compute the Fowler-Noll-Vo hash FNV-1a of a slice.
            pub fn [<fnv1a_ $size>](data: &[u8]) -> $ty {
                data.iter().fold($offset, |hash, byte| (hash ^ *byte as $ty).wrapping_mul($prime))
            }
        }
    };
}

fnv_impl! {u32, 32, 0x01000193, 0x811c9dc5}
fnv_impl! {u64, 64, 0x00000100000001B3, 0xcbf29ce484222325}
fnv_impl! {u128, 128, 0x0000000001000000000000000000013B, 0x6c62272e07bb014262b821756295c58d}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from
    /// https://datatracker.ietf.org/doc/draft-eastlake-fnv/21/
    #[test]
    fn test() {
        assert_eq!(fnv1a_32("".as_bytes()), 0x811c9dc5);
        assert_eq!(fnv1a_32("a".as_bytes()), 0xe40c292c);
        assert_eq!(fnv1a_32("foobar".as_bytes()), 0xbf9cf968);

        assert_eq!(fnv1a_64("".as_bytes()), 0xcbf29ce484222325);
        assert_eq!(fnv1a_64("a".as_bytes()), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv1a_64("foobar".as_bytes()), 0x85944171f73967e8);
    }
}
