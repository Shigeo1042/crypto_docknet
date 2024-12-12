use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use std::time::Instant;

use super::{
    known_signer::CredentialShowProtocol,
    signer_hidden_with_decoys::CredentialShowProtocolWithHiddenPublicKey,
};
use crate::{
    accumulator::{
        Accumulator, NonMembershipWitness, PreparedPublicKey as PRpk, PublicKey as RPk,
        SecretKey as RSk,
    },
    one_of_n_proof::OneOfNSrs,
    protego::{
        issuance::tests::{issuance_given_setup, setup},
        keys::{IssuerPublicKey, IssuerSecretKey, PreparedIssuerPublicKey},
        show::signer_hidden_with_policy::{
            CredentialShowProtocolWithDelegationPolicy, DelegationPolicyPublicKey,
            DelegationPolicySecretKey,
        },
    },
    set_commitment::{PreparedSetCommitmentSRS, SetCommitmentSRS},
};
use schnorr_pok::compute_random_oracle_challenge;

type Fr = <Bls12_381 as Pairing>::ScalarField;
type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;

pub fn init_accum(
    rng: &mut StdRng,
) -> (
    SetCommitmentSRS<Bls12_381>,
    Fr,
    <Bls12_381 as Pairing>::G1Affine,
    RSk<Bls12_381>,
    RPk<Bls12_381>,
    Accumulator<Bls12_381>,
    Vec<Fr>,
    Fr,
    NonMembershipWitness<Bls12_381>,
) {
    let (accum_srs, accum_trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
        StdRng,
        Blake2b512,
    >(rng, 100, Some("Protego".as_bytes()));

    let rsk = RSk::new(rng);
    let rpk = RPk::new(&rsk, accum_srs.get_P2());
    let Q = <Bls12_381 as Pairing>::G1Affine::rand(rng);

    let prpk = PRpk::from(rpk.clone());

    let nym = Fr::rand(rng);
    let members = vec![Fr::rand(rng), Fr::rand(rng)];

    let (accum, _) =
        Accumulator::new_using_trapdoor(&members, &accum_trapdoor, &rsk, accum_srs.get_P1());
    let non_mem_wit = NonMembershipWitness::from_members_using_trapdoor(
        &nym,
        &members,
        &accum_trapdoor,
        accum_srs.get_P2(),
    )
    .unwrap();
    assert!(non_mem_wit.verify(
        &nym,
        accum.accumulated(),
        prpk,
        accum_srs.get_s_P1(),
        accum_srs.get_P1(),
        G2Prepared::from(*accum_srs.get_P2())
    ));
    (
        accum_srs,
        accum_trapdoor,
        Q,
        rsk,
        rpk,
        accum,
        members,
        nym,
        non_mem_wit,
    )
}

pub fn show(
    rng: &mut StdRng,
    max_attributes: u32,
    attributes: Vec<Fr>,
    disclosed_attrs: Vec<Fr>,
    auditable: bool,
    supports_revocation: bool,
    signer_hidden: usize, // 0 means not hidden, 1 means hidden using decoys and 2 means hidden using a policy
    num_decoys: usize,
) {
    let (set_comm_srs, _td, ask, apk, isk, ipk, usk, upk) =
        setup(rng, max_attributes, auditable, supports_revocation);
    let (rpk, Q, nym, accum, non_mem_wit, s_P1, s_P2) = if supports_revocation {
        let (accum_srs, accum_trapdoor, Q, _, rpk, accum, _, nym, non_mem_wit) = init_accum(rng);

        assert_eq!(*accum_srs.get_P1(), *set_comm_srs.get_P1());
        assert_eq!(*accum_srs.get_P2(), *set_comm_srs.get_P2());
        assert_ne!(accum_trapdoor, _td);

        (
            Some(rpk),
            Some(Q),
            Some(nym),
            Some(accum),
            Some(non_mem_wit),
            Some(*accum_srs.get_s_P1()),
            Some(*accum_srs.get_s_P2()),
        )
    } else {
        (None, None, None, None, None, None, None)
    };

    let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());
    let prep_ipk = PreparedIssuerPublicKey::from(ipk.clone());
    let prep_rpk = rpk.as_ref().map(|r| PRpk::from(r.clone()));

    let cred = issuance_given_setup(
        rng,
        attributes.clone(),
        auditable,
        &apk,
        &isk,
        &ipk,
        &usk,
        &upk,
        Q.as_ref(),
        nym.as_ref(),
        s_P1.as_ref(),
        s_P2.as_ref(),
        &set_comm_srs,
    );
    let disclosed_attrs_count = disclosed_attrs.len();

    let nonce = vec![1, 2, 3];

    match signer_hidden {
        // When credential signer (public key) is known
        0 => {
            let start = Instant::now();
            let show_proto = if supports_revocation {
                CredentialShowProtocol::init_with_revocation(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    accum.clone().unwrap().accumulated(),
                    &non_mem_wit.unwrap(),
                    &usk,
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &Q.unwrap(),
                    &set_comm_srs,
                )
                .unwrap()
            } else {
                CredentialShowProtocol::init(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &set_comm_srs,
                )
                .unwrap()
            };

            let mut chal_bytes = vec![];
            show_proto
                .challenge_contribution(
                    accum.as_ref().map(|a| a.accumulated()),
                    Q.as_ref(),
                    auditable.then_some(&apk),
                    set_comm_srs.get_P1(),
                    &nonce,
                    &mut chal_bytes,
                )
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let show = show_proto
                .gen_show(
                    (auditable || supports_revocation).then_some(&usk),
                    &challenge,
                )
                .unwrap();
            let show_time = start.elapsed();

            if disclosed_attrs_count == 0 {
                assert!(show.core.disclosed_attributes_witness.is_none());
            }

            let start = Instant::now();
            if supports_revocation {
                show.verify_with_revocation(
                    &challenge,
                    disclosed_attrs,
                    prep_ipk,
                    accum.unwrap().accumulated(),
                    &Q.unwrap(),
                    prep_rpk.unwrap(),
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            } else {
                show.verify(
                    &challenge,
                    disclosed_attrs,
                    prep_ipk,
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            }
            let verify_time = start.elapsed();

            println!("For {}auditable show{} from credential with {} attributes and {} disclosed and known signer", if auditable {""} else {"non-"}, if supports_revocation {" with revocation"} else {""}, attributes.len(), disclosed_attrs_count);
            println!("Show time: {:?}", show_time);
            println!("Verify time: {:?}", verify_time);

            if auditable {
                assert_eq!(show.ct.unwrap().decrypt(&ask.0), upk.0)
            }
        }
        // When credential signer (public key) is hidden among decoys
        1 => {
            let decoy_issuer_keys = (0..num_decoys)
                .map(|_| {
                    let isk = IssuerSecretKey::<Bls12_381>::new::<StdRng>(
                        rng,
                        supports_revocation,
                        auditable,
                    )
                    .unwrap();
                    let ipk = IssuerPublicKey::new(&isk, set_comm_srs.get_P2());
                    ipk
                })
                .collect::<Vec<_>>();

            let (one_of_n_srs, _) = OneOfNSrs::<Bls12_381>::new(rng, set_comm_srs.get_P1());

            let start = Instant::now();
            let show_proto = if supports_revocation {
                CredentialShowProtocolWithHiddenPublicKey::init_with_revocation(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    accum.clone().unwrap().accumulated(),
                    &non_mem_wit.unwrap(),
                    &ipk,
                    &decoy_issuer_keys,
                    &one_of_n_srs,
                    &usk,
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &Q.unwrap(),
                    &set_comm_srs,
                )
                .unwrap()
            } else {
                CredentialShowProtocolWithHiddenPublicKey::init(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    &ipk,
                    &decoy_issuer_keys,
                    &one_of_n_srs,
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &set_comm_srs,
                )
                .unwrap()
            };

            let mut chal_bytes = vec![];
            show_proto
                .challenge_contribution(
                    accum.as_ref().map(|a| a.accumulated()),
                    Q.as_ref(),
                    auditable.then_some(&apk),
                    set_comm_srs.get_P1(),
                    &nonce,
                    &mut chal_bytes,
                )
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let show = show_proto
                .gen_show(
                    (auditable || supports_revocation).then_some(&usk),
                    &challenge,
                )
                .unwrap();
            let show_time = start.elapsed();

            let start = Instant::now();
            if supports_revocation {
                let mut possible_keys = decoy_issuer_keys.clone();
                possible_keys.insert(0, ipk);
                show.verify_with_revocation(
                    &challenge,
                    disclosed_attrs,
                    &possible_keys,
                    accum.unwrap().accumulated(),
                    &Q.unwrap(),
                    prep_rpk.unwrap(),
                    &one_of_n_srs,
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            } else {
                let mut possible_keys = decoy_issuer_keys.clone();
                possible_keys.insert(0, ipk);
                show.verify(
                    &challenge,
                    disclosed_attrs,
                    &possible_keys,
                    &one_of_n_srs,
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            }
            let verify_time = start.elapsed();

            println!("For {}auditable show{} from credential with {} attributes and {} disclosed and signer hidden in {} decoys", if auditable {""} else {"non-"}, if supports_revocation {" with revocation"} else {""}, attributes.len(), disclosed_attrs_count, decoy_issuer_keys.len());
            println!("Show time: {:?}", show_time);
            println!("Verify time: {:?}", verify_time);

            if auditable {
                assert_eq!(show.credential_show.ct.unwrap().decrypt(&ask.0), upk.0)
            }
        }
        // When credential signer (public key) is hidden using policy
        2 => {
            let policy_sk =
                DelegationPolicySecretKey::new(rng, ipk.public_key.size() as u32).unwrap();
            let policy_pk = DelegationPolicyPublicKey::new(&policy_sk, set_comm_srs.get_P1());
            let policy_sig = policy_sk
                .sign_public_key(rng, &ipk, set_comm_srs.get_P1(), set_comm_srs.get_P2())
                .unwrap();

            let start = Instant::now();
            let show_proto = if supports_revocation {
                CredentialShowProtocolWithDelegationPolicy::init_with_revocation(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    accum.clone().unwrap().accumulated(),
                    &non_mem_wit.unwrap(),
                    &ipk,
                    &policy_sig,
                    &usk,
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &Q.unwrap(),
                    &set_comm_srs,
                )
                .unwrap()
            } else {
                CredentialShowProtocolWithDelegationPolicy::init(
                    rng,
                    cred,
                    disclosed_attrs.clone(),
                    &ipk,
                    &policy_sig,
                    auditable.then_some(&upk),
                    auditable.then_some(&apk),
                    &set_comm_srs,
                )
                .unwrap()
            };

            let mut chal_bytes = vec![];
            show_proto
                .challenge_contribution(
                    accum.as_ref().map(|a| a.accumulated()),
                    Q.as_ref(),
                    auditable.then_some(&apk),
                    set_comm_srs.get_P1(),
                    &nonce,
                    &mut chal_bytes,
                )
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let show = show_proto
                .gen_show(
                    (auditable || supports_revocation).then_some(&usk),
                    &challenge,
                )
                .unwrap();
            let show_time = start.elapsed();

            let start = Instant::now();
            if supports_revocation {
                show.verify_with_revocation(
                    &challenge,
                    disclosed_attrs,
                    &policy_pk,
                    accum.unwrap().accumulated(),
                    &Q.unwrap(),
                    prep_rpk.unwrap(),
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            } else {
                show.verify(
                    &challenge,
                    disclosed_attrs,
                    &policy_pk,
                    auditable.then_some(&apk),
                    prep_set_comm_srs,
                )
                .unwrap()
            }
            let verify_time = start.elapsed();

            println!("For {}auditable show{} from credential with {} attributes and {} disclosed and signer hidden with a policy", if auditable {""} else {"non-"}, if supports_revocation {" with revocation"} else {""}, attributes.len(), disclosed_attrs_count);
            println!("Show time: {:?}", show_time);
            println!("Verify time: {:?}", verify_time);
        }
        _ => unreachable!(),
    }
}

#[test]
fn credential_show_with_known_signer() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    for disclosed in vec![
        vec![],
        vec![attributes[0]],
        vec![attributes[1], attributes[3]],
        vec![attributes[1], attributes[3], attributes[4]],
    ] {
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            disclosed.clone(),
            false,
            false,
            0,
            0,
        );
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            disclosed,
            true,
            false,
            0,
            0,
        );
    }
}

#[test]
fn credential_show_with_known_signer_and_revocation() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        false,
        true,
        0,
        0,
    );
    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        true,
        true,
        0,
        0,
    );
}

#[test]
fn credential_show_with_hidden_signer() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    for num_decoys in 10..20 {
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            vec![attributes[1], attributes[3]],
            false,
            false,
            1,
            num_decoys,
        );
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            vec![attributes[1], attributes[3]],
            true,
            false,
            1,
            num_decoys,
        );
    }
}

#[test]
fn credential_show_with_hidden_signer_and_revocation() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    for num_decoys in 10..20 {
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            vec![attributes[1], attributes[3]],
            false,
            true,
            1,
            num_decoys,
        );
        show(
            &mut rng,
            max_attributes,
            attributes.clone(),
            vec![attributes[1], attributes[3]],
            true,
            true,
            1,
            num_decoys,
        );
    }
}

#[test]
fn credential_show_with_delegation_policy() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        false,
        false,
        2,
        0,
    );
    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        true,
        false,
        2,
        0,
    );
}

#[test]
fn credential_show_with_delegation_policy_and_revocation() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let max_attributes = 10;
    let attributes = (0..max_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        false,
        true,
        2,
        0,
    );
    show(
        &mut rng,
        max_attributes,
        attributes.clone(),
        vec![attributes[1], attributes[3]],
        true,
        true,
        2,
        0,
    );
}

#[test]
pub fn my_test(){
    use dock_crypto_utils::elgamal::{SecretKey as AuditorSecretKey, PublicKey as AuditorPublicKey};
    use rand::{self, Rng};
    use crate::protego::keys::{IssuerSecretKey, IssuerPublicKey, UserSecretKey, UserPublicKey};
    use crate::protego::issuance;
    // let message_len = [5, 10, 50, 100, 500, 1000, 5000, 10000];
    let message_len = [5, 10];
    // let issuer_num = [5, 10, 50, 100];
    let issuer_num = [5, 10];
    let mut rng =  StdRng::seed_from_u64(0u64);

    for message_len_temp in message_len.iter(){
        let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));
                
        let mut message_fr_temp: Vec<Fr> = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }

        let open_message_6 = message_len_temp * 3 / 5;
        let mut open_message_len_temp = Vec::new();
        if open_message_6 == 3{
            open_message_len_temp.append(&mut [3, message_len_temp - 3].to_vec());
        }else{
            open_message_len_temp.append(&mut [3, open_message_6, message_len_temp - 3].to_vec());
        }
        open_message_len_temp.sort();
        
        for open_message_len_i in open_message_len_temp.iter(){

            for issuer_num_temp in issuer_num.iter(){
                let mut open_temp = Vec::new();
                for j in 0..*open_message_len_i{
                    let mut flg = true;
                    let mut x = rng.gen_range(0..*message_len_temp) as usize;
                    while flg {
                        flg = false;
                        for i in 0..j{
                            if x == open_temp[i as usize]{
                                flg = true;
                                x = rng.gen_range(0..*message_len_temp) as usize;
                                break;
                            }
                        }
                    }
                    open_temp.push(x);
                }
                open_temp.sort();

                let isk = IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                let ipk = IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
        
                let vsk = DelegationPolicySecretKey::<Bls12_381>::new(&mut rng, issuer_num_temp.clone() as u32).unwrap();
                let vpk = DelegationPolicyPublicKey::<Bls12_381>::new(&vsk, set_comm_srs.get_P1());
    
                let usk = UserSecretKey::<Bls12_381>::new(&mut rng, false);
                let upk = UserPublicKey::<Bls12_381>::new(&usk, set_comm_srs.get_P1());
        
                let ask = AuditorSecretKey::new(&mut rng);
                let apk = AuditorPublicKey::new(&ask, set_comm_srs.get_P1());

                let prep_set_comm_srs = PreparedSetCommitmentSRS::<Bls12_381>::from(set_comm_srs.clone());
                let prep_ipk = PreparedIssuerPublicKey::<Bls12_381>::from(ipk.clone());
                let sig_req_p = issuance::SignatureRequestProtocol::<Bls12_381>::init(&mut rng, &usk, false, &set_comm_srs.get_P1());
                let mut chal_bytes = vec![];
                sig_req_p.challenge_contribution(&upk, &set_comm_srs.get_P1(), None, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let (sig_req, sig_req_opn) = sig_req_p.gen_request(&mut rng, message_fr_temp.clone(), &usk, &challenge, &set_comm_srs).unwrap();
                sig_req.verify(message_fr_temp.clone(), &upk, &challenge, None, None, set_comm_srs.clone()).unwrap();
                let sig = sig_req.clone().sign(&mut rng, &isk, false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap();
                let cred = issuance::Credential::<Bls12_381>::new(sig_req.clone(), sig_req_opn.clone(), sig.clone(), message_fr_temp.clone(), prep_ipk.clone(), false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), prep_set_comm_srs.clone().prepared_P2).unwrap();
    
                let mut trusted_issuers = Vec::new();
                for _ in 0..*issuer_num_temp{
                    let isk_temp = IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                    let ipk_temp = IssuerPublicKey::<Bls12_381>::new(&isk_temp, &set_comm_srs.get_P2());
                    trusted_issuers.push(ipk_temp);
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                trusted_issuers[r] = ipk.clone();
                let mut trusted_issuer_list = Vec::new();
                for i in 0..*issuer_num_temp{
                    trusted_issuer_list.push((&trusted_issuers[i], DelegationPolicySecretKey::<Bls12_381>::sign_public_key(&vsk, &mut rng, &trusted_issuers[i], &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap()));
                }
                let nonce = vec![1, 2, 3];
                let mut trusted_issuer_sig = trusted_issuer_list[0].clone();
                for trusted_issuer in trusted_issuer_list.iter(){
                    if *trusted_issuer.0 == ipk{
                        trusted_issuer_sig = trusted_issuer.clone();
                    }
                }
                assert!(trusted_issuer_sig.0 == &ipk);
                let mut message_open_temp = Vec::new();
                for i in open_temp.iter(){
                    message_open_temp.push(message_fr_temp[*i]);
                }
                let show_proto = CredentialShowProtocolWithDelegationPolicy::<Bls12_381>::init(&mut rng, cred.clone(), message_open_temp.clone(), &ipk, &trusted_issuer_sig.1, false.then_some(&upk), false.then_some(&apk), &set_comm_srs).unwrap();

                let mut chal_bytes = vec![];
                show_proto.challenge_contribution(None, None, None, &set_comm_srs.get_P1(), &nonce, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let show = show_proto.gen_show(None, &challenge).unwrap();
        
                let bench_name = format!(
                    "Verify_Present_messagelen{}_issuernum{}_openmessage{}",
                    message_len_temp, issuer_num_temp, open_message_len_i
                );
                println!("{}", bench_name);
                let verify = show.verify(&challenge, message_open_temp.clone(), &vpk, false.then_some(&apk), prep_set_comm_srs.clone()).unwrap();
                // println!("Verify: {}", verify);
                println!("test");
                // assert!(verify == true);
            }
        }
    }
}