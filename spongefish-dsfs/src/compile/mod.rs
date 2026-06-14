//! Role-specific DSFS compiler wrappers.
//!
//! The shared scaffolding lives here — the `role_wrapper!` macro, the eight
//! compiled wrapper structs, and the prefix-free plain-instance framing. The
//! per-role constructors and trait impls live in [`argument`] and [`reduction`].

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use ia_core::{Encoding, NonInteractiveSession, ProtocolCore};
use spongefish::DuplexSpongeInterface;

use crate::params::Keccak;

mod argument;
mod reduction;
#[cfg(test)]
mod tests;

pub use argument::{
    argument_prover, argument_prover_with_salt, argument_verifier, argument_verifier_with_salt,
    preprocessing_argument_prover, preprocessing_argument_prover_with_salt,
    preprocessing_argument_verifier, preprocessing_argument_verifier_with_salt,
};
pub use reduction::{
    preprocessing_reduction_prover, preprocessing_reduction_prover_with_salt,
    preprocessing_reduction_verifier, preprocessing_reduction_verifier_with_salt, reduction_prover,
    reduction_prover_with_salt, reduction_verifier, reduction_verifier_with_salt,
};

/// Byte-oriented duplex sponge (`U = u8`).
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// Domain tag prepended to a plain-path instance before it is absorbed as a
/// public message, alongside a `u64` length prefix.
///
/// # Why the framing exists
///
/// Before the first challenge, DSFS absorbs the public instance into the sponge
/// so the Fiat–Shamir transcript is bound to *this* statement. For that binding
/// to be unambiguous, the absorbed instance bytes must be **prefix-free**: the
/// encoding of one instance must never be a prefix of another's. The sponge eats
/// a flat byte stream (`domsep ‖ instance ‖ salt ‖ messages …`) with no implicit
/// boundary between the instance and what follows, so a non-prefix-free instance
/// encoding (e.g. the identity encoding of `Vec<u8>` / `&[u8]`, whose length is
/// not self-described) could let two distinct statements share a transcript.
///
/// spongefish documents prefix-freeness as the caller's responsibility. Rather
/// than trust every protocol author to pick a prefix-free `Instance` encoding,
/// the plain compiler frames the instance itself — `TAG ‖ u64_le(len) ‖ bytes`,
/// the same shape [`ia_core::IndexedInstanceRef`] already uses on the
/// preprocessing path. This makes the two paths consistent and the plain path
/// robust by construction regardless of the instance type.
///
/// # Tradeoff
///
/// Framing is **absorb-only**: it changes nothing in the Argus interfaces (the
/// `Instance` type, the role traits, the `Dsfs*` constructors, and every call
/// site are untouched) — only the bytes fed to the sponge change. The costs are
/// (1) a few extra absorbed bytes per proof and (2) a transcript-format change.
/// The change is versioned by [`PLAIN_INSTANCE_TAG`] itself: an unframed (old)
/// and framed (new) compiler derive different challenges, so proofs do not cross
/// over. Bumping `SpongeInfo::SPONGE_INFO` is deliberately *not* used for this:
/// `SPONGE_INFO` is keyed by sponge, so a bump would also re-version the
/// preprocessing path and the σ-proofs `StdHash` interop path (which do not go
/// through these helpers and must stay byte-stable). The tag scopes the change
/// to exactly the plain compile path.
const PLAIN_INSTANCE_TAG: &[u8] = b"dsfs:plain-instance:v1";

/// Length-framed, domain-tagged view of a plain-path instance.
///
/// Encodes as `PLAIN_INSTANCE_TAG ‖ u64_le(inner.len()) ‖ inner.encode()`, which
/// is prefix-free for any inner encoding. See [`PLAIN_INSTANCE_TAG`].
struct FramedInstance<'a, I: ?Sized>(&'a I);

impl<I> Encoding<[u8]> for FramedInstance<'_, I>
where
    I: Encoding<[u8]> + ?Sized,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let inner = self.0.encode();
        let inner = inner.as_ref();
        let len = u64::try_from(inner.len()).expect("instance encoding length exceeds u64");
        let mut out = Vec::with_capacity(PLAIN_INSTANCE_TAG.len() + 8 + inner.len());
        out.extend_from_slice(PLAIN_INSTANCE_TAG);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(inner);
        out
    }
}

macro_rules! role_wrapper {
    ($name:ident, $field:ident) => {
        /// A DSFS-compiled executable role.
        ///
        /// Construct this wrapper through the corresponding semantic constructor
        /// rather than depending on its storage layout.
        pub struct $name<P, S, DS = Keccak, const SALT_LEN: usize = 0> {
            $field: P,
            duplex_sponge: DS,
            _session: PhantomData<S>,
        }

        impl<P, S, DS, const SALT_LEN: usize> $name<P, S, DS, SALT_LEN> {
            #[must_use]
            pub const fn new($field: P, duplex_sponge: DS) -> Self {
                Self {
                    $field,
                    duplex_sponge,
                    _session: PhantomData,
                }
            }
        }

        impl<P, S, DS, const SALT_LEN: usize> ProtocolCore for $name<P, S, DS, SALT_LEN>
        where
            P: ProtocolCore,
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                self.$field.protocol_id()
            }
        }

        impl<P, S, DS, const SALT_LEN: usize> NonInteractiveSession for $name<P, S, DS, SALT_LEN> {
            type Session = S;
        }
    };
}

role_wrapper!(ArgumentProver, argument);
role_wrapper!(ArgumentVerifier, argument);
role_wrapper!(ReductionProver, reduction);
role_wrapper!(ReductionVerifier, reduction);
role_wrapper!(PreprocessingArgumentProver, argument);
role_wrapper!(PreprocessingArgumentVerifier, argument);
role_wrapper!(PreprocessingReductionProver, reduction);
role_wrapper!(PreprocessingReductionVerifier, reduction);
