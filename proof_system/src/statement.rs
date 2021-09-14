use ark_ec::{AffineCurve, PairingEngine};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};

use bbs_plus::setup::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};

use ark_std::collections::BTreeSet;
pub use serialization::*;
use vb_accumulator::{
    proofs::{MembershipProvingKey, NonMembershipProvingKey},
    setup::{PublicKey as AccumPublicKey, SetupParams as AccumParams},
};

use crate::impl_collection;

/// Reference to a witness described as the tuple (`statement_id`, `witness_id`)
pub type WitnessRef = (usize, usize);

/// Type of proof and the public (known to both prover and verifier) values for the proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement<E: PairingEngine, G: AffineCurve> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    /// Membership in Accumulator
    AccumulatorMembership(AccumulatorMembership<E>),
    /// Non-membership in Accumulator
    AccumulatorNonMembership(AccumulatorNonMembership<E>),
    /// Proof of knowledge of committed elements in a Pedersen commitment
    PedersenCommitment(PedersenCommitment<G>),
}

/// Statement describing relation between statements
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaStatement {
    WitnessEquality(EqualWitnesses),
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MetaStatements(pub Vec<MetaStatement>);

// impl_collection!(Statements, Statement);
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Statements<E, G>(pub Vec<Statement<E, G>>)
where
    E: PairingEngine,
    G: AffineCurve;

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub params: BBSSignatureParamsG1<E>,
    pub public_key: BBSPublicKeyG2<E>,
    /// Messages being revealed.
    pub revealed_messages: BTreeMap<usize, E::Fr>,
}

/// Public values like setup params, public key, proving key and accumulator for proving membership
/// in positive and universal accumulator.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: MembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
}

/// Public values like setup params, public key, proving key and accumulator for proving non-membership
/// in universal accumulator.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorNonMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: NonMembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
}

/// Proving knowledge of scalars `s_i` in Pedersen commitment `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenCommitment<G: AffineCurve> {
    /// The bases `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    pub bases: Vec<G>,
    /// The Pedersen commitment `C` in `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    pub commitment: G,
}

/// Describes equality between one or more witnesses across statements. Eg. if witness 3 of statement
/// 0 is to be proven equal to witness 5 of statement 1, then its written as
/// ```
/// use ark_std::collections::BTreeSet;
/// use proof_system::statement::EqualWitnesses;
/// let mut eq = BTreeSet::new();
/// eq.insert((0, 3));
/// eq.insert((1, 5));
/// let eq_w = EqualWitnesses(vec![eq]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualWitnesses(pub Vec<BTreeSet<WitnessRef>>);

impl MetaStatements {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: MetaStatement) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<E, G> Statements<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Statement<E, G>) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a `Statement` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: BBSSignatureParamsG1<E>,
        public_key: BBSPublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E, G> {
        Statement::PoKBBSSignatureG1(Self {
            params,
            public_key,
            revealed_messages,
        })
    }
}

/// Create a `Statement` variant for proving membership in accumulator
impl<E: PairingEngine> AccumulatorMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving non-membership in accumulator
impl<E: PairingEngine> AccumulatorNonMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorNonMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineCurve> PedersenCommitment<G> {
    pub fn new_as_statement<E: PairingEngine>(bases: Vec<G>, commitment: G) -> Statement<E, G> {
        Statement::PedersenCommitment(Self { bases, commitment })
    }
}

mod serialization {
    use super::*;

    // TODO: Following code contains duplication that can possible be removed using macros

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for Statement<E, G> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorMembership(s) => 1u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorNonMembership(s) => {
                    2u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::PedersenCommitment(s) => 3u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for Statement<E, G> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    AccumulatorMembership::<E>::deserialize(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    AccumulatorNonMembership::<E>::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    PedersenCommitment::<G>::deserialize(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    AccumulatorMembership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    AccumulatorNonMembership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    PedersenCommitment::<G>::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    AccumulatorMembership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    AccumulatorNonMembership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    PedersenCommitment::<G>::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }

    impl CanonicalSerialize for MetaStatement {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    0u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::WitnessEquality(s) => 0u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::WitnessEquality(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl CanonicalDeserialize for MetaStatement {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize(&mut reader)? {
                0u8 => Ok(Self::WitnessEquality(EqualWitnesses::deserialize(
                    &mut reader,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::WitnessEquality(
                    EqualWitnesses::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::WitnessEquality(
                    EqualWitnesses::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
