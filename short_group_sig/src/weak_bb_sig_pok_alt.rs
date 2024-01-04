//! Proof of knowledge of weak-BB signature as described in the paper [Scalable Revocation Scheme for Anonymous Credentials Based on n-times Unlinkable Proofs](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf)
//! The advantage of this variation is that the prover does not need to compute any pairings
// TODO: Add proof of correctness (should i really call proof of correctness as this makes the proof/simulation happen), i.e. a tuple (G, G*x) and proof that x is the secret key

use crate::error::ShortGroupSigError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use schnorr_pok::{SchnorrCommitment, SchnorrResponse};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoKOfSignatureG1Protocol<E: Pairing> {
    /// Randomized signature. Called `sigma'` in the paper
    #[zeroize(skip)]
    pub A_prime: E::G1Affine,
    /// Called `sigma_bar` in the paper
    #[zeroize(skip)]
    pub A_bar: E::G1Affine,
    /// For proving relation `sigma_bar = g1 * r - sigma' * m`
    pub sc_comm: SchnorrCommitment<E::G1Affine>,
    /// Randomness and message `(r, m)`
    sc_wits: (E::ScalarField, E::ScalarField),
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKOfSignatureG1Proof<E: Pairing> {
    pub A_prime: E::G1Affine,
    pub A_bar: E::G1Affine,
    pub t: E::G1Affine,
    pub sc_resp: SchnorrResponse<E::G1Affine>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: impl AsRef<E::G1Affine>,
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
        g1: impl Into<E::G1Affine>,
    ) -> Result<Self, ShortGroupSigError> {
        let r = E::ScalarField::rand(rng);
        let blinding = blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        // A * r
        let A_prime = signature.as_ref().mul_bigint(r.into_bigint());
        let A_prime_neg = A_prime.neg();
        let g1 = g1.into();
        // A_bar = g1 * r - A_prime * m
        let A_bar = g1 * r + A_prime_neg * message;
        let sc_comm = SchnorrCommitment::new(
            &[g1, A_prime_neg.into()],
            vec![E::ScalarField::rand(rng), blinding],
        );
        let sc_wits = (r, message);
        Ok(Self {
            A_prime: A_prime.into_affine(),
            A_bar: A_bar.into_affine(),
            sc_comm,
            sc_wits,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g1: impl Into<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(
            &self.A_bar,
            &self.A_prime,
            g1,
            &self.sc_comm.t,
            writer,
        )
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignatureG1Proof<E>, ShortGroupSigError> {
        let sc_resp = self
            .sc_comm
            .response(&[self.sc_wits.0, self.sc_wits.1], challenge)?;
        Ok(PoKOfSignatureG1Proof {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            t: self.sc_comm.t,
            sc_resp,
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        A_prime: &E::G1Affine,
        A_bar: &E::G1Affine,
        g1: impl Into<E::G1Affine>,
        t: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        A_bar.serialize_compressed(&mut writer)?;
        A_prime.serialize_compressed(&mut writer)?;
        g1.into().serialize_compressed(&mut writer)?;
        t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> PoKOfSignatureG1Proof<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<E::G2Prepared>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_prime.is_zero() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        self.sc_resp.is_valid(
            &[g1.into(), self.A_prime.into_group().neg().into()],
            &self.A_bar,
            &self.t,
            challenge,
        )?;
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.A_bar),
                E::G1Prepared::from(-(self.A_prime.into_group())),
            ],
            [g2.into(), pk.into()],
        )
        .is_zero()
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<E::G2Prepared>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_prime.is_zero() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        self.sc_resp.is_valid(
            &[g1.into(), self.A_prime.into_group().neg().into()],
            &self.A_bar,
            &self.t,
            challenge,
        )?;
        pairing_checker.add_sources(&self.A_prime, pk.into(), &self.A_bar, g2);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g1: impl Into<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1Protocol::<E>::compute_challenge_contribution(
            &self.A_bar,
            &self.A_prime,
            g1,
            &self.t,
            writer,
        )
    }

    pub fn get_resp_for_message(&self) -> Result<&E::ScalarField, ShortGroupSigError> {
        self.sc_resp.get_response(1).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::SignatureParams,
        weak_bb_sig::{PreparedPublicKeyG2, PublicKeyG2, SecretKey, SignatureG1},
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn proof_of_knowledge_of_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = SignatureParams::<Bls12_381>::new::<Blake2b512>(b"test-params");

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);
        let prepared_pk = PreparedPublicKeyG2::from(pk.clone());
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&message, &sk, &params);

        let protocol =
            PoKOfSignatureG1Protocol::<Bls12_381>::init(&mut rng, sig, message, None, params.g1)
                .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(params.g1, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover).unwrap();

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(params.g1, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        proof
            .verify(
                &challenge_verifier,
                prepared_pk.0.clone(),
                params.g1,
                params.g2,
            )
            .unwrap();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        proof
            .verify_with_randomized_pairing_checker(
                &challenge_verifier,
                prepared_pk.0,
                params.g1,
                params.g2,
                &mut pairing_checker,
            )
            .unwrap();
        assert!(pairing_checker.verify());
    }
}
