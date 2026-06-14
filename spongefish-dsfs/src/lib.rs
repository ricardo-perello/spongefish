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
//! The semantic constructors are the byte-oriented convenience API. The module
//! path carries the axis (plain at the crate root, preprocessing under
//! [`preprocessing`]); the leaf name carries the role:
//!
//! - [`argument_prover`] / [`argument_verifier`] compile the two plain argument
//!   roles independently.
//! - [`reduction_prover`] / [`reduction_verifier`] do the same for reductions.
//! - [`preprocessing::argument_prover`] / [`preprocessing::argument_verifier`]
//!   (and the reduction pair) compile keyed roles independently. An
//!   `ia_core::Indexer` remains outside DSFS.
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
//! # Instance binding (prefix-free framing)
//!
//! Before the first challenge, the compiler absorbs the public instance so the
//! transcript is bound to the statement. For that binding to be unambiguous the
//! absorbed instance bytes must be **prefix-free** — no instance's encoding may
//! be a prefix of another's — because the sponge sees a flat byte stream with no
//! implicit boundary after the instance.
//!
//! Rather than rely on each protocol author to supply a prefix-free `Instance`
//! encoding (the identity encoding of `Vec<u8>` / `&[u8]`, for example, is *not*
//! prefix-free), both DSFS paths frame the instance with a tag and a `u64`
//! length prefix before absorbing it:
//!
//! - the **preprocessing** path via [`ia_core::IndexedInstanceRef`], and
//! - the **plain** path via an internal `dsfs:plain-instance:v1`-tagged wrapper.
//!
//! Framing is *absorb-only*: it changes no public type, trait, or constructor
//! signature — only the bytes fed to the sponge. The plain-path tag also
//! versions the transcript format, so it is independent of
//! [`SpongeInfo::SPONGE_INFO`] (which stays stable for the σ-proofs interop and
//! preprocessing paths). The low-level [`SpongeProver`] / [`SpongeVerifier`]
//! channels do **not** frame for you; callers that bypass these constructors
//! (e.g. σ-proofs byte-compat layouts) own their instance encoding.
//!
//! Transcript invariants maintained here:
//!
//! - public inputs are absorbed before the first challenge, with a prefix-free
//!   (tagged, length-prefixed) instance encoding;
//! - every prover message is absorbed before the next verifier challenge;
//! - verifier replay is deterministic;
//! - verification consumes exactly the expected proof bytes.

#![no_std]

extern crate alloc;

mod channel;
mod compile;
mod narg_security;
mod params;
mod session;

pub use channel::{SpongeProver, SpongeVerifier};
pub use compile::{
    argument_prover, argument_prover_with_salt, argument_verifier, argument_verifier_with_salt,
    reduction_prover, reduction_prover_with_salt, reduction_verifier, reduction_verifier_with_salt,
    ArgumentProver, ArgumentVerifier, ByteDuplexSponge, ReductionProver, ReductionVerifier,
};

/// DSFS-compiled executable roles and constructors for **preprocessing
/// (indexed)** protocols.
///
/// These mirror the plain API at the crate root ([`crate::ArgumentProver`] /
/// [`crate::argument_prover`], etc.); the module path is the only thing that
/// marks them as the preprocessing variants. An `ia_core::Indexer` remains
/// outside DSFS.
pub mod preprocessing {
    pub use crate::compile::{
        preprocessing_argument_prover as argument_prover,
        preprocessing_argument_prover_with_salt as argument_prover_with_salt,
        preprocessing_argument_verifier as argument_verifier,
        preprocessing_argument_verifier_with_salt as argument_verifier_with_salt,
        preprocessing_reduction_prover as reduction_prover,
        preprocessing_reduction_prover_with_salt as reduction_prover_with_salt,
        preprocessing_reduction_verifier as reduction_verifier,
        preprocessing_reduction_verifier_with_salt as reduction_verifier_with_salt,
        PreprocessingArgumentProver as ArgumentProver,
        PreprocessingArgumentVerifier as ArgumentVerifier,
        PreprocessingReductionProver as ReductionProver,
        PreprocessingReductionVerifier as ReductionVerifier,
    };
}
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
