//! Credential show (presentation) protocol when the signer (public key) is hidden from the verifier by
//! using a delegation policy. The delegation policy is a list of pairs of issuer public key and signature
//! where the signature is produced by the verifier. The user proves that the signature in the credential
//! was created by an issuer whose public key was signed by the verifier.
//! This is what the paper calls Protego Duo

use crate::accumulator::NonMembershipWitness;
use crate::auditor::AuditorPublicKey;
use crate::error::DelegationError;
use crate::mercurial_sig::{PublicKey, PublicKeyG1, SecretKey, SignatureG2};
use crate::protego::issuance::Credential;
use crate::protego::keys::{IssuerPublicKey, UserPublicKey, UserSecretKey};
use crate::protego::show::known_signer::{CredentialShow, CredentialShowProtocol};
use crate::set_commitment::SetCommitmentSRS;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::UniformRand;
use zeroize::Zeroize;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct DelegationPolicySecretKey<E: PairingEngine>(pub SecretKey<E>);

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DelegationPolicyPublicKey<E: PairingEngine>(pub PublicKeyG1<E>);

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DelegationPolicyProof<E: PairingEngine> {
    pub randomized_pk: IssuerPublicKey<E>,
    pub signature: SignatureG2<E>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShowProtocolWithDelegationPolicy<E: PairingEngine> {
    pub credential_show_protocol: CredentialShowProtocol<E>,
    pub pubkey_anonymity_proof: DelegationPolicyProof<E>,
}

impl<E: PairingEngine> DelegationPolicySecretKey<E> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        max_public_key_size: usize,
    ) -> Result<Self, DelegationError> {
        let sk = SecretKey::new(rng, max_public_key_size)?;
        Ok(Self(sk))
    }

    pub fn sign_public_key<R: RngCore>(
        &self,
        rng: &mut R,
        pk: &IssuerPublicKey<E>,
        P1: &E::G1Affine,
        P2: &E::G2Affine,
    ) -> Result<SignatureG2<E>, DelegationError> {
        let sig = SignatureG2::new(rng, &pk.public_key.0, &self.0, &P2, P1)?;
        Ok(sig)
    }
}

impl<E: PairingEngine> DelegationPolicyPublicKey<E> {
    pub fn new(secret_key: &DelegationPolicySecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(PublicKeyG1::new(&secret_key.0, P1))
    }
}

impl<E: PairingEngine> CredentialShowProtocolWithDelegationPolicy<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::Fr>,
        issuer_public_key: &IssuerPublicKey<E>,
        signature: &SignatureG2<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        CredentialShowProtocol::check_key_compat(
            issuer_public_key,
            credential.auditable_sig,
            false,
        )?;
        let (rho, pubkey_anonymity_proof) = Self::policy_proof(rng, signature, issuer_public_key);
        let c_show = CredentialShowProtocol::_init(
            rng,
            credential,
            disclosed_attributes,
            Some(&rho),
            None,
            None,
            None,
            user_pk,
            auditor_pk,
            None,
            set_comm_srs,
        )?;
        Ok(Self {
            credential_show_protocol: c_show,
            pubkey_anonymity_proof,
        })
    }

    pub fn init_with_revocation<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::Fr>,
        accumulated: &E::G1Affine,
        non_mem_wit: &NonMembershipWitness<E>,
        issuer_public_key: &IssuerPublicKey<E>,
        signature: &SignatureG2<E>,
        user_sk: &UserSecretKey<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        Q: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        CredentialShowProtocol::check_key_compat(
            issuer_public_key,
            credential.auditable_sig,
            true,
        )?;
        let (rho, pubkey_anonymity_proof) = Self::policy_proof(rng, signature, issuer_public_key);
        let c_show = CredentialShowProtocol::_init(
            rng,
            credential,
            disclosed_attributes,
            Some(&rho),
            Some(accumulated),
            Some(non_mem_wit),
            Some(user_sk),
            user_pk,
            auditor_pk,
            Some(Q),
            set_comm_srs,
        )?;
        Ok(Self {
            credential_show_protocol: c_show,
            pubkey_anonymity_proof,
        })
    }

    pub fn gen_show(
        self,
        user_secret_key: Option<&UserSecretKey<E>>,
        challenge: &E::Fr,
    ) -> Result<CredentialShowWithDelegationPolicy<E>, DelegationError> {
        Ok(CredentialShowWithDelegationPolicy {
            credential_show: self
                .credential_show_protocol
                .gen_show(user_secret_key, challenge)?,
            pubkey_anonymity_proof: self.pubkey_anonymity_proof,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulated: Option<&E::G1Affine>,
        Q: Option<&E::G1Affine>,
        apk: Option<&AuditorPublicKey<E>>,
        P1: &E::G1Affine,
        context: &[u8],
        mut writer: W,
    ) -> Result<(), DelegationError> {
        self.credential_show_protocol.challenge_contribution(
            accumulated,
            Q,
            apk,
            P1,
            context,
            &mut writer,
        )?;
        Ok(())
    }

    fn policy_proof<R: RngCore>(
        rng: &mut R,
        signature: &SignatureG2<E>,
        issuer_public_key: &IssuerPublicKey<E>,
    ) -> (E::Fr, DelegationPolicyProof<E>) {
        let rho = E::Fr::rand(rng);
        let (new_sig, new_key) = signature.change_rep(rng, &rho, &issuer_public_key.public_key.0);
        let new_key = IssuerPublicKey {
            public_key: PublicKey(new_key),
            supports_revocation: issuer_public_key.supports_revocation,
            supports_audit: issuer_public_key.supports_audit,
        };
        (
            rho,
            DelegationPolicyProof {
                randomized_pk: new_key,
                signature: new_sig,
            },
        )
    }
}

impl<E: PairingEngine> CredentialShowWithDelegationPolicy<E> {
    pub fn verify(
        &self,
        challenge: &E::Fr,
        disclosed_attributes: Vec<E::Fr>,
        policy_public_key: &DelegationPolicyPublicKey<E>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.pubkey_anonymity_proof.signature.verify(
            &self.pubkey_anonymity_proof.randomized_pk.public_key.0,
            &policy_public_key.0,
            set_comm_srs.get_P2(),
            set_comm_srs.get_P1(),
        )?;
        self.credential_show._verify(
            challenge,
            disclosed_attributes,
            &self.pubkey_anonymity_proof.randomized_pk,
            None,
            None,
            None,
            auditor_pk,
            set_comm_srs,
        )
    }

    pub fn verify_with_revocation(
        &self,
        challenge: &E::Fr,
        disclosed_attributes: Vec<E::Fr>,
        policy_public_key: &DelegationPolicyPublicKey<E>,
        accumulated: &E::G1Affine,
        Q: &E::G1Affine,
        accumulator_pk: &crate::accumulator::PublicKey<E>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.pubkey_anonymity_proof.signature.verify(
            &self.pubkey_anonymity_proof.randomized_pk.public_key.0,
            &policy_public_key.0,
            set_comm_srs.get_P2(),
            set_comm_srs.get_P1(),
        )?;
        self.credential_show._verify(
            challenge,
            disclosed_attributes,
            &self.pubkey_anonymity_proof.randomized_pk,
            Some(accumulated),
            Some(Q),
            Some(accumulator_pk),
            auditor_pk,
            set_comm_srs,
        )
    }

    pub fn supports_revocation(&self) -> bool {
        self.credential_show.rev.is_some()
    }

    pub fn supports_audit(&self) -> bool {
        self.credential_show.ct.is_some()
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShowWithDelegationPolicy<E: PairingEngine> {
    pub credential_show: CredentialShow<E>,
    pub pubkey_anonymity_proof: DelegationPolicyProof<E>,
}
