use core::marker::PhantomData;
use core::{fmt::Debug, slice};
use std::sync::Mutex;

use winter_crypto::{Digest, ElementHasher, Hasher};
use winter_math::{FieldElement, StarkField};
use winter_utils::{ByteReader, Deserializable, DeserializationError, Serializable};

use ff::PrimeField;
use halo2_proofs::halo2curves::bn256::Fr;
use poseidon::Poseidon as PoseidonHasher;

// POSEIDON HASHER SINGLETON
// ===============================================================================================

type PoseidonBn254_4_3 = PoseidonHasher<Fr, 4, 3>;

lazy_static! {
    static ref HASHER: Mutex<PoseidonBn254_4_3> = Mutex::new(PoseidonBn254_4_3::new(8, 58));
}

fn poseidon_hash(data: &[[u8; 32]]) -> ByteDigest<32> {
    let q = data
        .into_iter()
        .map(|x| Fr::from_repr(*x).unwrap())
        .collect::<Vec<_>>();
    let mut hasher = HASHER.lock().unwrap();
    hasher.update(&q[..]);
    let a = hasher.squeeze();
    hasher.clear();
    ByteDigest::new(<[u8; 32]>::try_from(&a.to_repr()[..]).unwrap())
}

// POSEIDON WITH 256-BIT OUTPUT
// ===============================================================================================

pub struct Poseidon<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Poseidon<B> {
    type Digest = ByteDigest<32>;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let iter = bytes.array_chunks::<32>();
        let remainder = iter.remainder();
        let mut data = iter.cloned().collect::<Vec<_>>();
        if remainder.len() > 0 {
            let mut remainder_data = [0u8; 32];
            remainder_data[0..remainder.len()].copy_from_slice(&remainder);
            data.push(remainder_data);
        }
        poseidon_hash(&data)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut data = [[0; 32]; 2];
        data[0].copy_from_slice(values[0].0.as_slice());
        data[1].copy_from_slice(values[1].0.as_slice());
        poseidon_hash(&data)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [[0; 32]; 2];
        data[0].copy_from_slice(&seed.0);
        data[1][..8].copy_from_slice(&value.to_le_bytes());
        poseidon_hash(&data)
    }
}

impl<B: StarkField> ElementHasher for Poseidon<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        assert!(B::IS_CANONICAL);

        let data = elements
            .iter()
            .map(|x| <[u8; 32]>::try_from(x.as_bytes()).unwrap())
            .collect::<Vec<_>>();
        poseidon_hash(&data)
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
