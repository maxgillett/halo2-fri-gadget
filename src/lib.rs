use std::marker::PhantomData;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
    poly::Rotation,
};

// FRI PROTOCOL PARAMS
// =========================================================================

#[allow(unused)]
#[derive(Default)]
struct FriProof<F: FieldExt, H: Hasher> {
    pub layer_commitments: Vec<H::Digest>,
    pub queries: Vec<FriQuery<F, H>>,
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
struct FriQuery<F: FieldExt, H: Hasher> {
    pub evaluations: Vec<F>,
    pub merkle_proof: Vec<H::Digest>, // siblings
}

// HASH FUNCTIONS
// =========================================================================

trait Hasher: Clone {
    type Digest: Default;

    fn hash(bytes: &[u8]) -> Self::Digest;
    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest;
}

#[derive(Clone, Default)]
struct Poseidon {
    // TODO
}

impl Hasher for Poseidon {
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        Self::Digest::default()
    }
    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest {
        Self::Digest::default()
    }
}

// HASHER CHIP
// =========================================================================

trait HasherChip: Clone {
    type Hasher: Hasher + Clone + Default;
    type Config: Clone;

    fn from_config(config: Self::Config) -> Self;
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self::Config;
    fn hash<F: FieldExt>(
        &self,
        ctx: &mut Context<'_, F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct PoseidonChipConfig {
    // TODO
}

#[derive(Clone)]
struct PoseidonChip {
    // TODO
}

#[allow(unused)]
impl HasherChip for PoseidonChip {
    type Hasher = Poseidon;
    type Config = PoseidonChipConfig;

    fn from_config(config: Self::Config) -> Self {
        Self {}
    }
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config {}
    }
    fn hash<F: FieldExt>(
        &self,
        ctx: &mut Context<'_, F>,
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

trait RandomCoinChip<F: FieldExt, H: HasherChip>: Clone {
    //type Config: Clone;

    fn from_config(
        config: RandomCoinConfig<F, H>,
        seed: AssignedValue<F>,
        counter: AssignedValue<F>,
    ) -> Self;
    fn configure(meta: &mut ConstraintSystem<F>) -> RandomCoinConfig<F, H>;
    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        commitment: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct RandomCoinConfig<F: FieldExt, H: HasherChip> {
    pub hasher_config: H::Config,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct RandomCoin<F: FieldExt, H: HasherChip> {
    config: RandomCoinConfig<F, H>,
    pub seed: AssignedValue<F>,
    pub counter: AssignedValue<F>,
}

impl<F: FieldExt, H: HasherChip> RandomCoinChip<F, H> for RandomCoin<F, H> {
    //type Config = RandomCoinConfig<F, H>;

    fn from_config(
        config: RandomCoinConfig<F, H>,
        seed: AssignedValue<F>,
        counter: AssignedValue<F>,
    ) -> Self {
        Self {
            config,
            seed,
            counter,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RandomCoinConfig<F, H> {
        RandomCoinConfig {
            hasher_config: H::configure(meta),
            _marker: PhantomData,
        }
    }

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        commitment: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let hasher = H::from_config(self.config.hasher_config.clone());
        self.seed = hasher.hash(ctx, &[self.seed.clone(), commitment])?;
        let alpha = hasher.hash(ctx, &[self.seed.clone(), self.counter.clone()]);
        alpha
    }
}

// FRI VERIFIER CHIP
// =========================================================================

#[allow(dead_code)]
#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt, H: HasherChip, C: RandomCoinChip<F, H>> {
    pub gate_config: FlexGateConfig<F>,
    pub merkle_tree_config: MerkleTreeChipConfig<F, H>,
    pub public_coin_config: RandomCoinConfig<F, H>,
    pub hasher_config: H::Config,
    pub instance: Column<Instance>,
    _marker: PhantomData<C>,
}

#[allow(dead_code)]
struct VerifierChip<F: FieldExt, H: HasherChip, C: RandomCoinChip<F, H>> {
    config: VerifierChipConfig<F, H, C>,
    _marker: PhantomData<C>,
}

impl<F: FieldExt, H: HasherChip, C: RandomCoinChip<F, H>> VerifierChip<F, H, C> {
    fn from_config(config: VerifierChipConfig<F, H, C>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F, H, C> {
        VerifierChipConfig {
            gate_config: FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            ),
            merkle_tree_config: MerkleTreeChip::configure(meta),
            public_coin_config: C::configure(meta),
            hasher_config: H::configure(meta),
            instance,
            _marker: PhantomData,
        }
    }

    fn verify_proof(
        &self,
        ctx: &mut Context<'_, F>,
        proof: &FriProof<F, H::Hasher>,
        public_coin_seed: F,
    ) -> Result<(), Error> {
        // TODO: Read this in from proof
        let layer_commitments = vec![];

        let layer_alphas =
            self.layer_alphas(ctx, Value::known(public_coin_seed), layer_commitments)?;

        // Execute FRI verification protocol for each query round
        for _ in 0..proof.queries.len() {
            let layer_values = self.layer_values(ctx, vec![])?;
            self.evaluate_polynomials(ctx, &layer_alphas, vec![])?;
            self.verify_remainder(ctx, vec![], proof.options.max_remainder_degree);
        }

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers
    #[allow(unused)]
    fn layer_alphas(
        &self,
        ctx: &mut Context<'_, F>,
        initial_seed: Value<F>,
        commitments: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let (seed, counter) = {
            let cells = self.config.gate_config.assign_region_smart(
                ctx,
                vec![Witness(initial_seed), Constant(F::from(0))],
                vec![],
                vec![],
                vec![],
            )?;
            (cells[0].clone(), cells[1].clone())
        };
        let mut public_coin_chip =
            RandomCoin::from_config(self.config.public_coin_config.clone(), seed, counter);
        let mut alphas = vec![];
        for commitment in commitments {
            let alpha = public_coin_chip.draw_alpha(ctx, commitment)?;
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Check that claimed evaluations match the FRI query values in the Merkle tree
    #[allow(unused)]
    fn layer_values(
        &self,
        ctx: &mut Context<'_, F>,
        evaluations: Vec<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // TODO
        Ok(vec![])
    }

    /// Interpolate the evalutions into polynomials, and evaluate at alpha
    #[allow(unused)]
    fn evaluate_polynomials(
        &self,
        ctx: &mut Context<'_, F>,
        alphas: &[AssignedValue<F>],
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
        ctx: &mut Context<'_, F>,
        remainder_evaluations: Vec<F>,
        max_degree: usize,
    ) {
        // TODO
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE: usize = 1;

struct FriVerifierCircuit<F: FieldExt, H: HasherChip, C: RandomCoinChip<F, H>> {
    pub proof: FriProof<F, H::Hasher>,
    pub public_coin_seed: F,
    _marker: PhantomData<C>,
}

impl<F, H, C> Default for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip,
    C: RandomCoinChip<F, H>,
{
    fn default() -> Self {
        Self {
            proof: FriProof::default(),
            public_coin_seed: F::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, C> Circuit<F> for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip,
    C: RandomCoinChip<F, H>,
{
    type Config = VerifierChipConfig<F, H, C>;
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

        layouter.assign_region(
            || "gate",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
                    },
                );

                verifier_chip.verify_proof(&mut ctx, &self.proof, self.public_coin_seed)?;

                Ok(())
            },
        )?;

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
            layer_commitments: vec![],
            queries: vec![],
            options,
        };

        // Random coin
        let public_coin_seed = Fr::from(1);

        let circuit = FriVerifierCircuit::<Fr, PoseidonChip, RandomCoin<Fr, PoseidonChip>> {
            proof,
            public_coin_seed,
            _marker: PhantomData,
        };

        //let public_input = vec![];
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
