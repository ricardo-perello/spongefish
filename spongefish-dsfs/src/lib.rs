//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation.
//!
//! This crate implements the DSFS transformation of Chiesa-Orru 2025,
//! Construction 4.3, for `ia-core` public-coin interactive protocols.
//!
//! The split of responsibilities is:
//!
//! - `ia-core` defines the abstract protocol vocabulary: channel traits,
//!   interactive argument/reduction roles and their non-interactive counterparts.
//! - `spongefish-dsfs` owns the concrete transformation from those interactive
//!   protocols into non-interactive proofs using spongefish transcripts.
//! - Protocol implementations should only call the channel API. They should not
//!   instantiate sponges, derive Fiat-Shamir challenges directly, or inspect
//!   transcript internals.
//!
//! The semantic constructors are the byte-oriented convenience API:
//!
//! - [`plain_non_interactive_argument_prover`] and
//!   [`plain_non_interactive_argument_verifier`] compile the two plain argument
//!   roles independently.
//! - [`plain_non_interactive_reduction_prover`] and
//!   [`plain_non_interactive_reduction_verifier`] do the same for reductions.
//! - The `preprocessing_non_interactive_*_prover` and
//!   `preprocessing_non_interactive_*_verifier` constructors compile keyed roles
//!   independently. An `ia_core::Indexer` remains outside DSFS.
//! - `*_with_salt` constructor variants add an explicit prover-chosen salt
//!   message before protocol execution.
//! - The `duplex_sponge` argument selects a byte-oriented sponge such as [`Keccak`] or
//!   [`StdHash`].
//!
//! Prover functions return [`ia_core::NargProof`]. Its `as_bytes()` method
//! exposes the raw DSFS proof string expected by the verifier functions.
//! Verification always checks EOF, so trailing proof bytes are rejected.
//!
//! Every wrapper implements exactly one non-interactive executable role.
//!
//! Transcript invariants maintained here:
//!
//! - public inputs are absorbed before the first challenge;
//! - every prover message is absorbed before the next verifier challenge;
//! - verifier replay is deterministic;
//! - verification consumes exactly the expected proof bytes.

#![no_std]

extern crate alloc;

mod channel;
mod compile;
mod narg_security;
mod params;
mod runners;

pub use channel::{SpongeProver, SpongeVerifier, TranscriptSponge};
pub use compile::{
    plain_non_interactive_argument_prover, plain_non_interactive_argument_prover_with_salt,
    plain_non_interactive_argument_verifier, plain_non_interactive_argument_verifier_with_salt,
    plain_non_interactive_reduction_prover, plain_non_interactive_reduction_prover_with_salt,
    plain_non_interactive_reduction_verifier, plain_non_interactive_reduction_verifier_with_salt,
    preprocessing_non_interactive_argument_prover,
    preprocessing_non_interactive_argument_prover_with_salt,
    preprocessing_non_interactive_argument_verifier,
    preprocessing_non_interactive_argument_verifier_with_salt,
    preprocessing_non_interactive_reduction_prover,
    preprocessing_non_interactive_reduction_prover_with_salt,
    preprocessing_non_interactive_reduction_verifier,
    preprocessing_non_interactive_reduction_verifier_with_salt, ByteDuplexSponge,
    DsfsArgumentProver, DsfsArgumentVerifier, DsfsReductionProver, DsfsReductionVerifier,
    PreprocessedDsfsArgumentProver, PreprocessedDsfsArgumentVerifier,
    PreprocessedDsfsReductionProver, PreprocessedDsfsReductionVerifier,
};
pub use narg_security::{
    reduction_security_for_source_bound, reduction_security_for_source_bound_with,
    reduction_security_for_source_instance, reduction_security_for_source_instance_with,
    security_for_concrete_instance, security_for_concrete_instance_with,
    security_for_instance_bound, security_for_instance_bound_with, NargSecurity,
};
pub use params::{
    DuplexSpongeParamsExt, Keccak, SpongeInfo, SpongeParams, StdHash, STD_HASH_SPONGE_PARAMS,
    STD_SPONGE_PARAMS,
};
