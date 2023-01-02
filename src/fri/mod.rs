use halo2_proofs::arithmetic::FieldExt;

pub struct QueryWitness<F: FieldExt> {
    pub position: usize,
    pub layers: Vec<QueryLayerWitness<F>>,
}

pub struct QueryLayerWitness<F: FieldExt> {
    pub evaluations: Vec<F>,
    pub merkle_proof: Vec<[u8; 32]>,
}
