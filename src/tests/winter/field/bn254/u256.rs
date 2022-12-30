use uint::construct_uint;

construct_uint! {
    /// 256-bit unsigned integer
    pub struct U256(4);
}

impl U256 {
    #[inline(always)]
    pub fn is_even(&self) -> bool {
        *self & U256::one() != U256::one()
    }
}
