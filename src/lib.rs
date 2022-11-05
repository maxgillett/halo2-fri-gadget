use std::marker::PhantomData;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
    poly::Rotation,
};

//use halo2_gadgets::poseidon::{
//    primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
//    Hash,
//};
//use halo2_merkle_tree::chips::poseidon::{PoseidonChip, PoseidonConfig};
//use halo2curves::pasta::Fp;

// FRI PROTOCOL PARAMS
// =========================================================================

#[allow(unused)]
#[derive(Default)]
struct FriProof<F: FieldExt> {
    pub queries: Vec<FriQuery<F>>,
    pub options: FriOptions,
}

#[allow(unused)]
#[derive(Default)]
struct FriOptions {
    pub domain_size: usize,
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
}

#[allow(unused)]
struct FriQuery<F: FieldExt> {
    pub evaluations: Vec<F>,
    pub positions: Vec<usize>,
}

// HASH FUNCTIONS
// =========================================================================

trait HasherChip: Clone {
    type Config: Clone;

    fn from_config(config: Self::Config) -> Self;
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self::Config;
    fn hash<F: FieldExt>(
        &self,
        layouter: impl Layouter<F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct PoseidonConfig {
    // TODO
}

#[derive(Clone)]
struct Poseidon {
    // TODO
}

#[allow(unused)]
impl HasherChip for Poseidon {
    type Config = PoseidonConfig;

    fn from_config(config: Self::Config) -> Self {
        Self {}
    }
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config {}
    }
    fn hash<F: FieldExt>(
        &self,
        mut layouter: impl Layouter<F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        unimplemented!()
    }
}

// MERKLE TREE CHIP
// =========================================================================

#[allow(dead_code)]
#[derive(Clone)]
struct MerkleTreeChipConfig<F: FieldExt, H: HasherChip> {
    hasher_config: H::Config,
    _marker: PhantomData<F>,
}

#[allow(dead_code)]
struct MerkleTreeChip<F: FieldExt, H: HasherChip> {
    config: MerkleTreeChipConfig<F, H>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, H: HasherChip> MerkleTreeChip<F, H> {
    fn configure(meta: &mut ConstraintSystem<F>) -> MerkleTreeChipConfig<F, H> {
        MerkleTreeChipConfig {
            hasher_config: H::configure(meta),
            _marker: PhantomData,
        }
    }
}

// RANDOM COIN CHIP
// =========================================================================

trait RandomCoinChip {
    fn draw_alpha<F: FieldExt, H: HasherChip>(
        &self,
        layouter: impl Layouter<F>,
        commitment: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct RandomCoinChipConfig<F: FieldExt, H: HasherChip> {
    pub hasher_config: H::Config,
    pub seed: Column<Advice>,
    _marker: PhantomData<F>,
}

struct RandomCoin<F: FieldExt, H: HasherChip> {
    config: RandomCoinChipConfig<F, H>,
}

impl<F: FieldExt, H: HasherChip> RandomCoin<F, H> {
    fn from_config(config: RandomCoinChipConfig<F, H>) -> Self {
        Self { config }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RandomCoinChipConfig<F, H> {
        RandomCoinChipConfig {
            hasher_config: H::configure(meta),
            seed: meta.advice_column(),
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt, H: HasherChip> RandomCoinChip for RandomCoin<F, H> {
    fn draw_alpha(
        &self,
        mut layouter: impl Layouter<F>,
        commitment: &AssignedValue<F>,
    ) -> AssignedValue<F> {
        let hasher = H::from_config(self.config.hasher_config.clone());
        let seed = hasher.hash(&[
            meta.query_advice(self.config.seed, Rotation::cur()),
            commitment,
        ]);
        //let alpha = self.draw();
    }

    //fn reseed(&self, value: AssignedValue<F>) -> Result<(), Error> {
    //    // TODO
    //    Ok(())
    //}

    //fn draw(&self) -> Result<AssignedValue<F>, Error> {
    //    // TODO
    //}

    //fn next(&self) -> Result<AssignedValue<F>, Error> {
    //    // TODO
    //}
}

// FRI VERIFIER CHIP
// =========================================================================

#[allow(dead_code)]
#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt, H: HasherChip> {
    pub gate_config: FlexGateConfig<F>,
    pub public_coin_config: RandomCoinChipConfig<F, H>,
    pub merkle_tree_config: MerkleTreeChipConfig<F, H>,
    pub hasher_config: H::Config,
    pub instance: Column<Instance>,
}

#[allow(dead_code)]
struct VerifierChip<F: FieldExt, H: HasherChip> {
    config: VerifierChipConfig<F, H>,
}

impl<F: FieldExt, H: HasherChip> VerifierChip<F, H> {
    fn from_config(config: VerifierChipConfig<F, H>) -> Self {
        Self { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F, H> {
        VerifierChipConfig {
            gate_config: FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            ),
            public_coin_config: RandomCoin::configure(meta),
            merkle_tree_config: MerkleTreeChip::configure(meta),
            hasher_config: H::configure(meta),
            instance,
        }
    }

    fn verify_proof(
        &self,
        mut layouter: impl Layouter<F>,
        proof: &FriProof<F>,
    ) -> Result<(), Error> {
        // TODO: Read this in from public inputs
        let layer_commitments = vec![];

        let layer_alphas = self.layer_alphas(
            layouter.namespace(|| "reconstruct alphas"),
            layer_commitments,
        )?;

        // Execute FRI verification protocol for each query round
        for _ in 0..proof.queries.len() {
            let layer_values =
                self.layer_values(layouter.namespace(|| "check claimed evaluations"), vec![])?;
            self.evaluate_polynomials(
                layouter.namespace(|| "polynomial evaluation"),
                layer_alphas,
                vec![],
            )?;
            self.verify_remainder(
                layouter.namespace(|| "verify remainder"),
                vec![],
                proof.options.max_remainder_degree,
            );
        }

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers
    #[allow(unused)]
    fn layer_alphas(
        &self,
        mut layouter: impl Layouter<F>,
        commitments: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let public_coin_chip = RandomCoinChip::from_config(self.config.public_coin_config.clone());
        let alphas = vec![];
        for commitment in commitments {
            let alpha =
                public_coin_chip.draw_alpha(layouter.namespace(|| "draw alphas"), &commitment);
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Check that claimed evaluations match the FRI query values in the Merkle tree
    #[allow(unused)]
    fn layer_values(
        &self,
        mut layouter: impl Layouter<F>,
        evaluations: Vec<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // TODO
        Ok(vec![])
    }

    /// Interpolate the evalutions into polynomials, and evaluate at alpha
    #[allow(unused)]
    fn evaluate_polynomials(
        &self,
        mut layouter: impl Layouter<F>,
        alphas: Vec<AssignedValue<F>>,
        evaluations: Vec<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // TODO
        Ok(vec![])
    }

    /// Interpolate the remainder evaluations into a polynomial, and check that its degree
    /// is less than or equal to `max_degree`
    #[allow(unused)]
    fn verify_remainder(
        &self,
        mut layouter: impl Layouter<F>,
        remainder_evaluations: Vec<F>,
        max_degree: usize,
    ) {
        // TODO
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE: usize = 1;

struct FriVerifierCircuit<F: FieldExt, H: HasherChip> {
    pub proof: FriProof<F>,
    _marker: PhantomData<H>,
}

impl<F: FieldExt, H: HasherChip> Default for FriVerifierCircuit<F, H> {
    fn default() -> Self {
        Self {
            proof: FriProof::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt, H: HasherChip> Circuit<F> for FriVerifierCircuit<F, H> {
    type Config = VerifierChipConfig<F, H>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerifierChip::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let verifier_chip = VerifierChip::from_config(config);
        verifier_chip.verify_proof(layouter.namespace(|| "verify proof"), &self.proof)?;
        Ok(())
    }
}

mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    fn test() {
        let options = FriOptions {
            domain_size: 2,
            folding_factor: 2,
            max_remainder_degree: 256,
        };
        let proof = FriProof {
            queries: vec![],
            options,
        };

        let circuit = FriVerifierCircuit::<Fr, Poseidon> {
            proof,
            _marker: PhantomData,
        };

        //let public_input = vec![];
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
