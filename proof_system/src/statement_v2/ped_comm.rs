use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::ProofSystemError;
use crate::setup_params::SetupParams;
use crate::statement_v2::StatementV2;
use dock_crypto_utils::serde_utils::*;

/// Proving knowledge of scalars `s_i` in Pedersen commitment `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitment<G: AffineCurve> {
    /// The Pedersen commitment `C` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: G,
    /// Commitment key `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "Option<Vec<AffineGroupBytes>>")]
    pub key: Option<Vec<G>>,
    pub key_ref: Option<usize>,
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineCurve> PedersenCommitment<G> {
    pub fn new_statement_from_params<E: PairingEngine>(
        key: Vec<G>,
        commitment: G,
    ) -> StatementV2<E, G> {
        StatementV2::PedersenCommitment(Self {
            commitment,
            key: Some(key),
            key_ref: None,
        })
    }

    pub fn new_statement_from_params_refs<E: PairingEngine>(
        key_ref: usize,
        commitment: G,
    ) -> StatementV2<E, G> {
        StatementV2::PedersenCommitment(Self {
            commitment,
            key: None,
            key_ref: Some(key_ref),
        })
    }

    pub fn get_commitment_key<'a, E: PairingEngine>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a Vec<G>, ProofSystemError> {
        if let Some(k) = &self.key {
            return Ok(k);
        }
        if let Some(idx) = self.key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::PedersenCommitmentKey(k) => Ok(k),
                    _ => Err(ProofSystemError::IncompatiblePedCommSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}
