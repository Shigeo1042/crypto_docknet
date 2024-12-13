use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rand::{rngs::StdRng, SeedableRng},vec::Vec, UniformRand};
use rand::{self, Rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use blake2::Blake2b512;
use schnorr_pok;
use dock_crypto_utils::elgamal::{SecretKey as AuditorSecretKey, PublicKey as AuditorPublicKey};

fn protego_benchmark(c: &mut Criterion) {
    let message_len = [5, 10, 50, 100, 500, 1000, 5000, 10000];
    let issuer_num = [5, 10, 50, 100];
    let mut rng =  StdRng::seed_from_u64(0u64);

    for message_len_temp in message_len.iter(){

        let bench_name = format!(
            "Issuer_Key_Gen_messagelen{}",
            message_len_temp
        );
        c.bench_function(&bench_name, |b|{
            let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));
            b.iter(|| {
                let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk,&set_comm_srs.get_P2());
                black_box((isk,ipk));
            });
        });
    }

    for message_len_temp in message_len.iter(){

        let bench_name = format!(
            "User_Key_Gen_messagelen{}",
            message_len_temp
        );

        let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));

        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let usk = delegatable_credentials::protego::keys::UserSecretKey::<Bls12_381>::new(&mut rng, false);
                let upk = delegatable_credentials::protego::keys::UserPublicKey::<Bls12_381>::new(&usk, set_comm_srs.get_P1());
                black_box((usk,upk));
            });
        });
    }

    for message_len_temp in message_len.iter(){
        let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));
        let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
        let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
        let bench_name = format!(
            "Verifier_Key_Gen_messagelen{}",
            message_len_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let vsk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::new(&mut rng, ipk.public_key.size() as u32).unwrap();
                let vpk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicyPublicKey::<Bls12_381>::new(&vsk,&set_comm_srs.get_P1());
                black_box((vsk,vpk));
            });
        });
    }

    //Issue Credential
    for message_len_temp in message_len.iter(){
        let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));

        let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
        let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
    
        let usk = delegatable_credentials::protego::keys::UserSecretKey::<Bls12_381>::new(&mut rng, false);
        let upk = delegatable_credentials::protego::keys::UserPublicKey::<Bls12_381>::new(&usk, set_comm_srs.get_P1());

        let ask = AuditorSecretKey::new(&mut rng);
        let apk = AuditorPublicKey::new(&ask, set_comm_srs.get_P1());
        let mut message_fr_temp: Vec<Fr> = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }

        let bench_name = format!(
            "Issuer_Sign_messagelen{}",
            message_len_temp
        );

        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let prep_set_comm_srs = delegatable_credentials::set_commitment::PreparedSetCommitmentSRS::<Bls12_381>::from(set_comm_srs.clone());
                let prep_ipk = delegatable_credentials::protego::keys::PreparedIssuerPublicKey::<Bls12_381>::from(ipk.clone());
                let sig_req_p = delegatable_credentials::protego::issuance::SignatureRequestProtocol::<Bls12_381>::init(&mut rng, &usk, false, &set_comm_srs.get_P1());
                let mut chal_bytes = vec![];
                sig_req_p.challenge_contribution(&upk, &set_comm_srs.get_P1(), None, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let (sig_req, sig_req_opn) = sig_req_p.gen_request(&mut rng, message_fr_temp.clone(), &usk, &challenge, &set_comm_srs).unwrap();
                sig_req.verify(message_fr_temp.clone(), &upk, &challenge, None, None, set_comm_srs.clone()).unwrap();
                let sig = sig_req.clone().sign(&mut rng, &isk, false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap();
                let cred = delegatable_credentials::protego::issuance::Credential::<Bls12_381>::new(sig_req.clone(), sig_req_opn.clone(), sig.clone(), message_fr_temp.clone(), prep_ipk.clone(), false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), prep_set_comm_srs.clone().prepared_P2).unwrap();
                black_box(cred);
            });
        });
    }

    //Verify Credential if you need

    //Sign Policy
    for message_len_temp in message_len.iter(){
        let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));
        
        for issuer_num_temp in issuer_num.iter(){
            let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
            let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
    
            let vsk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::new(&mut rng, ipk.public_key.size() as u32).unwrap();
            // let vpk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicyPublicKey::<Bls12_381>::new(&vsk, set_comm_srs.get_P1());

            let mut trusted_issuers = Vec::new();
            for _ in 0..*issuer_num_temp{
                let isk_temp = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                let ipk_temp = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk_temp, &set_comm_srs.get_P2());
                trusted_issuers.push(ipk_temp);
            }
            let r = rng.gen_range(1..*issuer_num_temp);
            trusted_issuers[r] = ipk.clone();
    
            let bench_name = format!(
                "Verifier_Sign_Policy_mlen{}_issuernum{}",
                message_len_temp, issuer_num_temp
            );
    
            c.bench_function(&bench_name, |b|{
                b.iter(|| {
                    let mut sig = Vec::new();
                    for i in 0..*issuer_num_temp{
                        sig.push(delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::sign_public_key(&vsk, &mut rng, &trusted_issuers[i], &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap());
                    }
                    black_box(sig);
                });
            });
        }
    }

    // //Verify Policy if you need

    // //Present Credential
    for message_len_temp in message_len.iter(){
        let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, *message_len_temp, Some("Issuer-Hiding".as_bytes()));
                
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

                let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
        
                let vsk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::new(&mut rng, ipk.public_key.size() as u32).unwrap();
                // let vpk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicyPublicKey::<Bls12_381>::new(&vsk, set_comm_srs.get_P1());
    
                let usk = delegatable_credentials::protego::keys::UserSecretKey::<Bls12_381>::new(&mut rng, false);
                let upk = delegatable_credentials::protego::keys::UserPublicKey::<Bls12_381>::new(&usk, set_comm_srs.get_P1());
        
                let ask = AuditorSecretKey::new(&mut rng);
                let apk = AuditorPublicKey::new(&ask, set_comm_srs.get_P1());

                let prep_set_comm_srs = delegatable_credentials::set_commitment::PreparedSetCommitmentSRS::<Bls12_381>::from(set_comm_srs.clone());
                let prep_ipk = delegatable_credentials::protego::keys::PreparedIssuerPublicKey::<Bls12_381>::from(ipk.clone());
                let sig_req_p = delegatable_credentials::protego::issuance::SignatureRequestProtocol::<Bls12_381>::init(&mut rng, &usk, false, &set_comm_srs.get_P1());
                let mut chal_bytes = vec![];
                sig_req_p.challenge_contribution(&upk, &set_comm_srs.get_P1(), None, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let (sig_req, sig_req_opn) = sig_req_p.gen_request(&mut rng, message_fr_temp.clone(), &usk, &challenge, &set_comm_srs).unwrap();
                sig_req.verify(message_fr_temp.clone(), &upk, &challenge, None, None, set_comm_srs.clone()).unwrap();
                let sig = sig_req.clone().sign(&mut rng, &isk, false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap();
                let cred = delegatable_credentials::protego::issuance::Credential::<Bls12_381>::new(sig_req.clone(), sig_req_opn.clone(), sig.clone(), message_fr_temp.clone(), prep_ipk.clone(), false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), prep_set_comm_srs.clone().prepared_P2).unwrap();
    
                let mut trusted_issuers = Vec::new();
                for _ in 0..*issuer_num_temp{
                    let isk_temp = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                    let ipk_temp = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk_temp, &set_comm_srs.get_P2());
                    trusted_issuers.push(ipk_temp);
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                trusted_issuers[r] = ipk.clone();
                let mut trusted_issuer_list = Vec::new();
                for i in 0..*issuer_num_temp{
                    trusted_issuer_list.push((&trusted_issuers[i], delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::sign_public_key(&vsk, &mut rng, &trusted_issuers[i], &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap()));
                }

                let mut nonce = Vec::new();
                for i in 0..*message_len_temp{
                    nonce.push(i as u8);
                }
        
                let bench_name = format!(
                    "Present_Credential_messagelen{}_openmessage{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );
        
                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let mut trusted_issuer_sig = trusted_issuer_list[0].clone().1;
                        for trusted_issuer in trusted_issuer_list.iter(){
                            if *trusted_issuer.0 == ipk{
                                trusted_issuer_sig = trusted_issuer.clone().1;
                            }
                        }
                        let mut message_open_temp = Vec::new();
                        for i in open_temp.iter(){
                            message_open_temp.push(message_fr_temp[*i]);
                        }
                        let show_proto = delegatable_credentials::protego::show::signer_hidden_with_policy::CredentialShowProtocolWithDelegationPolicy::<Bls12_381>::init(&mut rng, cred.clone(), message_open_temp.clone(), &ipk, &trusted_issuer_sig, false.then_some(&upk), false.then_some(&apk), &set_comm_srs).unwrap();

                        let mut chal_bytes = vec![];
                        show_proto.challenge_contribution(None, None, None, &set_comm_srs.get_P1(), &nonce, &mut chal_bytes).unwrap();
                        let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                        let show = show_proto.gen_show(None, &challenge).unwrap();
                        black_box(show);
                    });
                });
            }
        }
    }

    //Verify Presentation
    for message_len_temp in message_len.iter(){
                
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
                let max_size = if message_len_temp.clone() >= issuer_num_temp.clone() as u32 { message_len_temp.clone() } else { issuer_num_temp.clone() as u32};
                let (set_comm_srs, _) = delegatable_credentials::set_commitment::SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<StdRng, Blake2b512>(&mut rng, max_size.clone(), Some("Issuer-Hiding".as_bytes()));
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

                let isk = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                let ipk = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk, &set_comm_srs.get_P2());
        
                let vsk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::new(&mut rng, ipk.public_key.size() as u32).unwrap();
                let vpk = delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicyPublicKey::<Bls12_381>::new(&vsk, set_comm_srs.get_P1());
    
                let usk = delegatable_credentials::protego::keys::UserSecretKey::<Bls12_381>::new(&mut rng, false);
                let upk = delegatable_credentials::protego::keys::UserPublicKey::<Bls12_381>::new(&usk, set_comm_srs.get_P1());
        
                let ask = AuditorSecretKey::new(&mut rng);
                let apk = AuditorPublicKey::new(&ask, set_comm_srs.get_P1());

                let prep_set_comm_srs = delegatable_credentials::set_commitment::PreparedSetCommitmentSRS::<Bls12_381>::from(set_comm_srs.clone());
                let prep_ipk = delegatable_credentials::protego::keys::PreparedIssuerPublicKey::<Bls12_381>::from(ipk.clone());
                let sig_req_p = delegatable_credentials::protego::issuance::SignatureRequestProtocol::<Bls12_381>::init(&mut rng, &usk, false, &set_comm_srs.get_P1());
                let mut chal_bytes = vec![];
                sig_req_p.challenge_contribution(&upk, &set_comm_srs.get_P1(), None, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let (sig_req, sig_req_opn) = sig_req_p.gen_request(&mut rng, message_fr_temp.clone(), &usk, &challenge, &set_comm_srs).unwrap();
                sig_req.verify(message_fr_temp.clone(), &upk, &challenge, None, None, set_comm_srs.clone()).unwrap();
                let sig = sig_req.clone().sign(&mut rng, &isk, false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap();
                let cred = delegatable_credentials::protego::issuance::Credential::<Bls12_381>::new(sig_req.clone(), sig_req_opn.clone(), sig.clone(), message_fr_temp.clone(), prep_ipk.clone(), false.then_some(&upk), false.then_some(&apk), &set_comm_srs.get_P1(), prep_set_comm_srs.clone().prepared_P2).unwrap();
    
                let mut trusted_issuers = Vec::new();
                for _ in 0..*issuer_num_temp{
                    let isk_temp = delegatable_credentials::protego::keys::IssuerSecretKey::<Bls12_381>::new(&mut rng, false, false).unwrap();
                    let ipk_temp = delegatable_credentials::protego::keys::IssuerPublicKey::<Bls12_381>::new(&isk_temp, &set_comm_srs.get_P2());
                    trusted_issuers.push(ipk_temp);
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                trusted_issuers[r as usize] = ipk.clone();
                let mut trusted_issuer_list = Vec::new();
                for i in 0..*issuer_num_temp{
                    trusted_issuer_list.push((&trusted_issuers[i as usize], delegatable_credentials::protego::show::signer_hidden_with_policy::DelegationPolicySecretKey::<Bls12_381>::sign_public_key(&vsk, &mut rng, &trusted_issuers[i as usize], &set_comm_srs.get_P1(), &set_comm_srs.get_P2()).unwrap()));
                }

                let nonce = vec![1, 2, 3];
                let mut trusted_issuer_sig = trusted_issuer_list[0].clone().1;
                for trusted_issuer in trusted_issuer_list.iter(){
                    if *trusted_issuer.0 == ipk{
                        trusted_issuer_sig = trusted_issuer.clone().1;
                    }
                }
                let mut message_open_temp = Vec::new();
                for i in open_temp.iter(){
                    message_open_temp.push(message_fr_temp[*i]);
                }
                let show_proto = delegatable_credentials::protego::show::signer_hidden_with_policy::CredentialShowProtocolWithDelegationPolicy::<Bls12_381>::init(&mut rng, cred.clone(), message_open_temp.clone(), &ipk, &trusted_issuer_sig, false.then_some(&upk), false.then_some(&apk), &set_comm_srs).unwrap();

                let mut chal_bytes = vec![];
                show_proto.challenge_contribution(None, None, None, &set_comm_srs.get_P1(), &nonce, &mut chal_bytes).unwrap();
                let challenge = schnorr_pok::compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                let show = show_proto.gen_show(None, &challenge).unwrap();
        
                let bench_name = format!(
                    "Verify_Present_messagelen{}_openmessage{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );
        
                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let verify = show.verify(&challenge, message_open_temp.clone(), &vpk, false.then_some(&apk), set_comm_srs.clone()).is_ok();
                        black_box(verify);
                    });
                });
            }
        }
    }
}

criterion_group!(benches, protego_benchmark);
criterion_main!(benches);