//! DSFS compiler: Duplex-Sponge Fiat-Shamir transformation.
//!
//! This crate implements the DSFS transformation of Chiesa-Orru 2025,
//! Construction 4.3, for `ia-core` public-coin interactive protocols.
//!
//! The split of responsibilities is:
//!
//! - `ia-core` defines the abstract protocol vocabulary: channel traits,
//!   interactive arguments/reductions, `NargProof`, and the
//!   `NonInteractiveArgument` / `NonInteractiveReduction` traits.
//! - `spongefish-dsfs` owns the concrete transformation from those interactive
//!   protocols into non-interactive proofs using spongefish transcripts.
//! - Protocol implementations should only call the channel API. They should not
//!   instantiate sponges, derive Fiat-Shamir challenges directly, or inspect
//!   transcript internals.
//!
//! The semantic constructors are the byte-oriented convenience API:
//!
//! - [`plain_non_interactive_argument`] builds a DSFS wrapper for a plain
//!   `InteractiveArgument` and immediately exposes `prove` / `verify`.
//! - [`plain_non_interactive_reduction`] builds a DSFS wrapper for a plain
//!   `InteractiveReduction` and immediately exposes `prove` / `verify`.
//! - [`preprocessing_non_interactive_argument`] builds a stateless DSFS wrapper
//!   for a `PreprocessingInteractiveArgument`; obtain `(pk, vk)` from the body's
//!   `index(&ix)` and pass the relevant key to `prove` / `verify` (the wrapper
//!   derives the committed index from whichever key it is handed).
//! - [`preprocessing_non_interactive_reduction`] builds a stateless DSFS wrapper
//!   for a `PreprocessingInteractiveReduction`; same keys-as-inputs shape.
//! - `*_with_salt` constructor variants add an explicit prover-chosen salt
//!   message before protocol execution.
//! - The `duplex_sponge` argument selects a byte-oriented sponge such as [`Keccak`] or
//!   [`StdHash`].
//!
//! Prover functions return [`ia_core::NargProof`]. Its `as_bytes()` method
//! exposes the raw DSFS proof string expected by the verifier functions.
//! Verification always checks EOF, so trailing proof bytes are rejected.
//!
//! Plain wrappers implement `NonInteractiveArgument` / `NonInteractiveReduction`.
//! Preprocessing wrappers are stateless and implement
//! `PreprocessingNonInteractiveArgument` / `PreprocessingNonInteractiveReduction`
//! (keys are inputs to `prove` / `verify`, not stored on the wrapper).
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

pub use channel::TranscriptSponge;
pub use channel::{SpongeProver, SpongeVerifier};
pub use compile::{
    plain_non_interactive_argument, plain_non_interactive_argument_with_salt,
    plain_non_interactive_reduction, plain_non_interactive_reduction_with_salt,
    preprocessing_non_interactive_argument, preprocessing_non_interactive_argument_with_salt,
    preprocessing_non_interactive_reduction, preprocessing_non_interactive_reduction_with_salt,
    ByteDuplexSponge, CombinedNarg, DsfsArgument, DsfsReduction, PreprocessedDsfsArgument,
    PreprocessedDsfsReduction,
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
