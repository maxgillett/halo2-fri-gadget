mod param;
use core::marker::PhantomData;
use core::{fmt::Debug, slice};

// Optimized version of poseidon with same output as the basic permutation
mod poseidon;

use winter_crypto::{Digest, ElementHasher, Hasher};
use winter_math::{FieldElement, StarkField};
use winter_utils::{ByteReader, Deserializable, DeserializationError, Serializable};

// POSEIDON WITH 256-BIT OUTPUT
// ===============================================================================================
/// (Taken from https://github.com/VictorColomb/stark-snark-recursive-proofs)
/// Implementation of the [Hasher](super::Hasher) trait for POSEIDON hash function with 256-bit
/// output.

pub struct Poseidon<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Poseidon<B> {
    type Digest = ByteDigest<32>;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // return the first [RATE] elements of the state as hash result
        poseidon::digest(bytes)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut data = [0; 64];
        data[..32].copy_from_slice(values[0].0.as_slice());
        data[32..].copy_from_slice(values[1].0.as_slice());
        poseidon::digest(&data)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        poseidon::digest(&data)
    }
}

impl<B: StarkField> ElementHasher for Poseidon<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        assert!(B::IS_CANONICAL);

        let bytes = E::elements_as_bytes(elements);
        poseidon::digest(bytes)
    }
}

// BYTE DIGEST
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ByteDigest<const N: usize>([u8; N]);

impl<const N: usize> ByteDigest<N> {
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn bytes_as_digests(bytes: &[[u8; N]]) -> &[ByteDigest<N>] {
        let p = bytes.as_ptr();
        let len = bytes.len();
        unsafe { slice::from_raw_parts(p as *const ByteDigest<N>, len) }
    }

    #[inline(always)]
    pub fn digests_as_bytes(digests: &[ByteDigest<N>]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> Digest for ByteDigest<N> {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];
        result[..N].copy_from_slice(&self.0);
        result
    }
}

impl<const N: usize> Default for ByteDigest<N> {
    fn default() -> Self {
        ByteDigest([0; N])
    }
}

impl<const N: usize> Serializable for ByteDigest<N> {
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.0);
    }
}

impl<const N: usize> Deserializable for ByteDigest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ByteDigest(source.read_u8_array()?))
    }
}
