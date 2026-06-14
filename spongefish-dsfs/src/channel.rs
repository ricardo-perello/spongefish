//! Low-level sponge-backed `ProverChannel` / `VerifierChannel` adapters.
//!
//! These adapters are public for transcript-format interoperability, notably
//! sigma-protocol compatibility. Ordinary protocol implementations should use
//! only the `ia-core` channel traits and should be compiled through the
//! semantic constructors in this crate.

extern crate alloc;

use alloc::vec::Vec;

use ia_core::{Deserialize, ProverChannel, VerifierChannel};
use spongefish::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, NargSerialize, ProverState,
    VerificationResult, VerifierState,
};

use crate::params::Keccak;

/// Wraps `spongefish::ProverState` as an ia-core `ProverChannel`.
///
/// Generic over the duplex sponge `DS` used for the Fiat–Shamir transcript.
/// Defaults to [`Keccak`] (Argus standard); use [`crate::params::StdHash`] for
/// compatibility with spongefish `std_prover` / `std_verifier` (SHAKE128 XOF).
///
/// This is a low-level compatibility API. Protocol authors should accept a
/// generic [`ProverChannel`] instead of naming this type.
pub struct SpongeProver<DS: DuplexSpongeInterface = Keccak> {
    pub(crate) state: ProverState<DS>,
}

impl<DS: DuplexSpongeInterface> SpongeProver<DS> {
    #[must_use]
    pub const fn new(state: ProverState<DS>) -> Self {
        Self { state }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn narg_string(&self) -> &[u8] {
        self.state.narg_string()
    }

    /// Absorb a **public** message into the transcript (Fiat–Shamir) without appending to the NARG string.
    ///
    /// Matches spongefish `ProverState::public_message` (e.g. σ-proofs batchable commitments).
    pub fn public_message<T: Encoding<[DS::U]> + ?Sized>(&mut self, msg: &T) {
        self.state.public_message(msg);
    }

    /// Squeeze a verifier challenge from the duplex sponge.
    pub fn verifier_message<VM: Decoding<[DS::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

impl<DS: DuplexSpongeInterface> ProverChannel for SpongeProver<DS> {
    type Unit = DS::U;

    fn send_prover_message<PM: Encoding<[DS::U]> + NargSerialize>(&mut self, msg: &PM) {
        self.state.prover_message(msg);
    }

    fn read_verifier_message<VM: Decoding<[DS::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}

/// Wraps `spongefish::VerifierState` as an ia-core `VerifierChannel`.
///
/// This is a low-level compatibility API. Protocol authors should accept a
/// generic [`VerifierChannel`] instead of naming this type.
pub struct SpongeVerifier<'a, DS: DuplexSpongeInterface = Keccak> {
    pub(crate) state: VerifierState<'a, DS>,
}

impl<'a, DS: DuplexSpongeInterface> SpongeVerifier<'a, DS> {
    #[must_use]
    pub const fn new(state: VerifierState<'a, DS>) -> Self {
        Self { state }
    }

    /// Absorb a public message without consuming the NARG cursor.
    pub fn public_message<T: Encoding<[DS::U]> + ?Sized>(&mut self, msg: &T) {
        self.state.public_message(msg);
    }

    /// Read an ordered list of prover messages from the NARG string and absorb each one.
    pub fn prover_messages_vec<T: Encoding<[DS::U]> + NargDeserialize>(
        &mut self,
        len: usize,
    ) -> VerificationResult<Vec<T>> {
        self.state.prover_messages_vec(len)
    }

    /// Squeeze a verifier challenge.
    pub fn verifier_message<VM: Decoding<[DS::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }

    pub fn check_eof(self) -> VerificationResult<()> {
        self.state.check_eof()
    }
}

impl<DS: DuplexSpongeInterface> VerifierChannel for SpongeVerifier<'_, DS> {
    type Unit = DS::U;

    fn read_prover_message<PM: Encoding<[DS::U]> + Deserialize>(
        &mut self,
    ) -> ia_core::VerificationResult<PM> {
        self.state
            .prover_message()
            .map_err(|_| ia_core::VerificationError)
    }

    fn send_verifier_message<VM: Decoding<[DS::U]>>(&mut self) -> VM {
        self.state.verifier_message()
    }
}
