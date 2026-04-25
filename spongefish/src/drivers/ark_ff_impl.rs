//! `ark_ff` bindings for sponge-specific unit support.

use ark_ff::{Fp, FpConfig};

impl<C: FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    const ZERO: Self = C::ZERO;
}
