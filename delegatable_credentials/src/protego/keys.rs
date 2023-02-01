use crate::error::DelegationError;
use crate::mercurial_sig::{PreparedPublicKey, PublicKey, SecretKey};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use zeroize::Zeroize;

/// Secret key of the credential issuer. The size of the key would be at least 3 and at most 7 depending on it
/// supporting revocation and/or audit as each feature adds 2 elements to the key
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuerSecretKey<E: PairingEngine> {
    pub secret_key: SecretKey<E>,
    /// Whether revocation is supported
    pub supports_revocation: bool,
    /// Whether auditability is supported
    pub supports_audit: bool,
}

/// Public key of the credential issuer. The size of the key would be at least 3 and at most 7 depending on it
/// supporting revocation and/or audit as each feature adds 2 elements to the key
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuerPublicKey<E: PairingEngine> {
    pub public_key: PublicKey<E>,
    /// Whether revocation is supported
    pub supports_revocation: bool,
    /// Whether auditability is supported
    pub supports_audit: bool,
}

#[derive(Clone, Debug)]
pub struct PreparedIssuerPublicKey<E: PairingEngine> {
    pub public_key: PreparedPublicKey<E>,
    pub supports_revocation: bool,
    pub supports_audit: bool,
}

impl<E: PairingEngine> Drop for IssuerSecretKey<E> {
    fn drop(&mut self) {
        self.secret_key.0.zeroize();
    }
}

impl<E: PairingEngine> IssuerSecretKey<E> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        supports_revocation: bool,
        supports_audit: bool,
    ) -> Result<Self, DelegationError> {
        Ok(Self {
            secret_key: SecretKey::new(rng, Self::get_size(supports_revocation, supports_audit))?,
            supports_revocation,
            supports_audit,
        })
    }

    pub fn generate_using_seed<D>(
        seed: &[u8],
        supports_revocation: bool,
        supports_audit: bool,
    ) -> Result<Self, DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        Ok(Self {
            secret_key: SecretKey::generate_using_seed::<D>(
                seed,
                Self::get_size(supports_revocation, supports_audit),
            )?,
            supports_revocation,
            supports_audit,
        })
    }

    fn get_size(supports_revocation: bool, supports_audit: bool) -> usize {
        let mut size = 3;
        if supports_revocation {
            size += 2;
        }
        if supports_audit {
            size += 2;
        }
        size
    }
}

impl<E: PairingEngine> IssuerPublicKey<E> {
    pub fn new(secret_key: &IssuerSecretKey<E>, P2: &E::G2Affine) -> Self {
        Self {
            public_key: PublicKey::new(&secret_key.secret_key, P2),
            supports_revocation: secret_key.supports_revocation,
            supports_audit: secret_key.supports_audit,
        }
    }

    pub fn prepared(&self) -> PreparedIssuerPublicKey<E> {
        PreparedIssuerPublicKey {
            supports_revocation: self.supports_revocation,
            supports_audit: self.supports_audit,
            public_key: self.public_key.prepared(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserSecretKey<E: PairingEngine>(pub E::Fr, pub Option<E::Fr>);

/// Each user, i.e. credential receiver has key pair and when the credential supports auditability, the
/// user during a credential show embed its public key which can only be recovered by the auditor
/// de-anonymizing the user. The optional element in G1 is only needed if the credential supports revocation.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserPublicKey<E: PairingEngine>(pub E::G1Affine, pub Option<E::G1Affine>);

impl<E: PairingEngine> Drop for UserSecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
    }
}

impl<E: PairingEngine> UserSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R, supports_revocation: bool) -> Self {
        Self(
            E::Fr::rand(rng),
            supports_revocation.then(|| E::Fr::rand(rng)),
        )
    }

    pub fn supports_revocation(&self) -> bool {
        self.1.is_some()
    }
}

impl<E: PairingEngine> UserPublicKey<E> {
    pub fn new(secret_key: &UserSecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(
            P1.mul(secret_key.0.into_repr()).into_affine(),
            secret_key.1.map(|s| P1.mul(s.into_repr()).into_affine()),
        )
    }

    pub fn supports_revocation(&self) -> bool {
        self.1.is_some()
    }
}
