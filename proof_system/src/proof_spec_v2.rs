use crate::meta_statement::{MetaStatement, MetaStatements};
use crate::setup_params::SetupParams;
use crate::statement_v2::{StatementV2, StatementsV2};
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

/// Describes the relations that need to proven. This is created independently by the prover and verifier and must
/// be agreed upon and be same before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofSpecV2<E: PairingEngine, G: AffineCurve> {
    pub statements: StatementsV2<E, G>,
    pub meta_statements: MetaStatements,
    pub setup_params: Vec<SetupParams<E, G>>,
    /// `context` is any arbitrary data that needs to be hashed into the proof and it must be kept
    /// same while creating and verifying the proof. Eg of `context` are the purpose of
    /// the proof or the verifier's identity or some verifier-specific identity of the holder
    /// or all of the above combined.
    pub context: Option<Vec<u8>>,
}

impl<E, G> ProofSpecV2<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new(
        statements: StatementsV2<E, G>,
        meta_statements: MetaStatements,
        setup_params: Vec<SetupParams<E, G>>,
        context: Option<Vec<u8>>,
    ) -> Self {
        Self {
            statements,
            meta_statements,
            setup_params,
            context,
        }
    }

    pub fn add_statement(&mut self, statement: StatementV2<E, G>) -> usize {
        self.statements.add(statement)
    }

    pub fn add_meta_statement(&mut self, meta_statement: MetaStatement) -> usize {
        self.meta_statements.add(meta_statement)
    }

    /// Sanity check to ensure the proof spec is valid. This should never be false as these are used
    /// by same entity creating them.
    pub fn is_valid(&self) -> bool {
        for mt in &self.meta_statements.0 {
            match mt {
                // All witness equalities should be valid
                MetaStatement::WitnessEquality(w) => {
                    if !w.is_valid() {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl<E, G> Default for ProofSpecV2<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    fn default() -> Self {
        Self {
            statements: StatementsV2::new(),
            meta_statements: MetaStatements::new(),
            setup_params: Vec::new(),
            context: None,
        }
    }
}
