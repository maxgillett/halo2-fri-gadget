use core::marker::PhantomData;
use core::{fmt::Debug, slice};

use winter_crypto::{Digest, ElementHasher, Hasher};
use winter_math::{fields::f64::BaseElement, FieldElement, StarkField};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::hash::poseidon_fp64::Poseidon64_256;
use ff::{Field, PrimeField};
use goldilocks::fp::{Goldilocks as Fp, MODULUS};

pub struct Poseidon;

fn poseidon_hash(inputs: &[Fp]) -> ElementDigest {
    let mut state = [Fp::zero(); Poseidon64_256::<Fp>::WIDTH];

    // Absorb all input chunks.
    for input_chunk in inputs.chunks(Poseidon64_256::<Fp>::SPONGE_RATE) {
        // Overwrite the first r elements with the inputs. This differs from a standard sponge,
        // where we would xor or add in the inputs. This is a well-known variant, though,
        // sometimes called "overwrite mode".
        state[..input_chunk.len()].copy_from_slice(input_chunk);
        state = Poseidon64_256::permute(state);
    }

    // Squeeze until we have the desired number of outputs.
    let mut outputs = [Fp::zero(); 4];
    loop {
        for i in 0..Poseidon64_256::<Fp>::SPONGE_RATE {
            outputs[i] = state[i];
            if i == 3 {
                return ElementDigest::new(outputs);
            }
        }
        state = Poseidon64_256::permute(state);
    }
}

impl Hasher for Poseidon {
    type Digest = ElementDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let iter = bytes.array_chunks::<8>();
        let remainder = iter.remainder();
        let mut inputs = iter.map(|x| Fp::from_bytes(x).unwrap()).collect::<Vec<_>>();
        if remainder.len() > 0 {
            let mut remainder_data = [0u8; 8];
            remainder_data[0..remainder.len()].copy_from_slice(&remainder);
            inputs.push(Fp::from_bytes(&remainder_data).unwrap());
        }
        poseidon_hash(&inputs)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut inputs = [Fp::zero(); 8];
        inputs[0..8].copy_from_slice(Self::Digest::digests_as_elements(values));
        poseidon_hash(&inputs)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut inputs = [Fp::zero(); 12];
        inputs[0..4].copy_from_slice(seed.as_elements());
        inputs[4] = Fp::from(value);
        if value > MODULUS {
            inputs[5] = Fp::from(value / MODULUS);
        }
        poseidon_hash(&inputs)
    }
}

impl ElementHasher for Poseidon {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        let inputs = E::as_base_elements(elements)
            .iter()
            .map(|x| Fp::from(x.as_int()))
            .collect::<Vec<_>>();
        poseidon_hash(&inputs)
    }
}

// ELEMENT DIGEST
// ================================================================================================

const DIGEST_SIZE: usize = 4;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ElementDigest([BaseElement; DIGEST_SIZE]);

impl ElementDigest {
    pub fn new(value: [Fp; DIGEST_SIZE]) -> Self {
        let inner: [BaseElement; DIGEST_SIZE] = value
            .iter()
            .map(|x| BaseElement::from(x.to_repr().0))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self(inner)
    }

    pub fn as_elements(&self) -> &[Fp] {
        let res = self
            .0
            .iter()
            .map(|x| Fp::from(x.as_int()))
            .collect::<Vec<_>>();
        let p = res.as_ptr();
        unsafe { slice::from_raw_parts(p as *const Fp, res.len()) }
    }

    pub fn digests_as_elements(digests: &[Self]) -> &[Fp] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_SIZE;
        let elements = unsafe { slice::from_raw_parts(p as *const BaseElement, len) };
        let res = elements
            .iter()
            .map(|x| Fp::from(x.as_int()))
            .collect::<Vec<_>>();

        let p = res.as_ptr();
        let len = res.len(); // * DIGEST_SIZE;
        unsafe { slice::from_raw_parts(p as *const Fp, len) }
    }
}

impl Digest for ElementDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }
}

impl Default for ElementDigest {
    fn default() -> Self {
        ElementDigest([BaseElement::default(); DIGEST_SIZE])
    }
}

impl Serializable for ElementDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.as_bytes());
    }
}

impl Deserializable for ElementDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // TODO: check if the field elements are valid?
        let e1 = BaseElement::new(source.read_u64()?);
        let e2 = BaseElement::new(source.read_u64()?);
        let e3 = BaseElement::new(source.read_u64()?);
        let e4 = BaseElement::new(source.read_u64()?);

        Ok(Self([e1, e2, e3, e4]))
    }
}

impl From<[BaseElement; DIGEST_SIZE]> for ElementDigest {
    fn from(value: [BaseElement; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl From<ElementDigest> for [BaseElement; DIGEST_SIZE] {
    fn from(value: ElementDigest) -> Self {
        value.0
    }
}

impl From<ElementDigest> for [u8; 32] {
    fn from(value: ElementDigest) -> Self {
        value.as_bytes()
    }
}
