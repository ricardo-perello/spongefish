//! The two transcript-lifecycle combinators every compiled role shares.
//!
//! Each DSFS prove/verify is the same bracket: derive the domain separator,
//! initialise the sponge, write/read the optional salt, run the role against the
//! channel, then snapshot the NARG bytes (prove) or check EOF (verify). The only
//! things that vary across plain/preprocessing and argument/reduction are the
//! public input the transcript binds and what the role does with the channel —
//! so those are the `public_input` argument and the `run` closure. Everything
//! else lives here, once.

use ia_core::{Encoding, NargDeserialize, NargProof, VerificationError, VerificationResult};
use rand::RngCore;
use spongefish::DomainSeparator;

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::SpongeInfo;

/// Run a Fiat–Shamir **prover** session: derive domain separator, init sponge,
/// write the salt, run `run` against the channel, return `(proof bytes, run's output)`.
pub fn prove_session<O, DS, S, PI, const SALT_LEN: usize>(
    duplex_sponge: DS,
    protocol_id: impl AsRef<[u8]>,
    session: &S,
    public_input: &PI,
    run: impl FnOnce(&mut SpongeProver<DS>) -> O,
) -> (NargProof, O)
where
    DS: SpongeInfo,
    S: Encoding<[u8]>,
    PI: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        protocol_id.as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(public_input);

    let mut ch = SpongeProver::new(domsep.to_prover(duplex_sponge));
    let mut salt = [0u8; SALT_LEN];
    ch.state.rng().fill_bytes(&mut salt);
    ch.state.prover_message(&salt);

    let out = run(&mut ch);
    (NargProof::from_bytes(ch.narg_string().to_vec()), out)
}

/// Run a Fiat–Shamir **verifier** session: derive domain separator, init sponge,
/// read the salt, run `run` against the channel, then require the proof is fully
/// consumed (EOF).
pub fn verify_session<O, DS, S, PI, const SALT_LEN: usize>(
    duplex_sponge: DS,
    protocol_id: impl AsRef<[u8]>,
    session: &S,
    public_input: &PI,
    proof: &[u8],
    run: impl FnOnce(&mut SpongeVerifier<DS>) -> VerificationResult<O>,
) -> VerificationResult<O>
where
    DS: SpongeInfo,
    S: Encoding<[u8]>,
    PI: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        protocol_id.as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(public_input);

    let mut ch = SpongeVerifier::new(domsep.to_verifier(duplex_sponge, proof));
    let _salt: [u8; SALT_LEN] = ch.state.prover_message().map_err(|_| VerificationError)?;

    let out = run(&mut ch)?;
    ch.check_eof().map_err(|_| VerificationError)?;
    Ok(out)
}
