//! Unit-level checks of the failure models, the assemblies and the games.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use vyra_core::{DeterministicEntropy, Kem};
use vyra_kem::{HybridKem, KemSuite};
use vyra_yield::adversaries::flip_last;
use vyra_yield::combiners::CombinerKind;
use vyra_yield::games::{
    BindingModel, BindingTarget, HonestBindingClaim, HonestBindingGame, IndCca2Game,
    MaliciousBindingClaim, MaliciousBindingGame, OracleAnswer,
};
use vyra_yield::models::key_substitutable::substitute_secret_key;
use vyra_yield::models::leaky::leak;
use vyra_yield::models::{Base, ModelKind, SenderKeyed};
use vyra_yield::scenario::{AttackContext, Scenario};

#[test]
fn every_model_is_correct() {
    for base in [Base::MlKem512, Base::Hqc128] {
        for m in ModelKind::ALL {
            let kem = m.instantiate(base);
            let mut rng = DeterministicEntropy::from_seed(m.name().as_bytes());
            let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
            assert_eq!(pk.len(), kem.public_key_len());
            assert_eq!(kem.public_key_from_secret(sk.expose()).unwrap(), pk);
            kem.validate_public_key(&pk).unwrap();
            let (ct, k) = kem.encapsulate(&pk, &mut rng).unwrap();
            assert_eq!(ct.len(), kem.ciphertext_len());
            assert!(
                kem.decapsulate(sk.expose(), &ct).unwrap().ct_eq(&k),
                "{m:?} {base:?}"
            );
        }
    }
}

#[test]
fn models_break_what_they_say() {
    let base = Base::MlKem512;
    let mut rng = DeterministicEntropy::from_seed(b"break");
    // Leaky: key is public.
    let leaky = ModelKind::Leaky.instantiate(base);
    let (pk, _) = leaky.generate_keypair(&mut rng).unwrap();
    let (ct, k) = leaky.encapsulate(&pk, &mut rng).unwrap();
    assert_eq!(k.expose(), leak(&pk, &ct));
    // Malleable: mauled ciphertext, same key.
    let mal = ModelKind::Malleable.instantiate(base);
    let (pk, sk) = mal.generate_keypair(&mut rng).unwrap();
    let (ct, k) = mal.encapsulate(&pk, &mut rng).unwrap();
    let mauled = flip_last(&ct);
    assert_ne!(mauled, ct);
    assert!(mal.decapsulate(sk.expose(), &mauled).unwrap().ct_eq(&k));
    // KeySubstitutable: other secret key, other public key, same key.
    let ks = ModelKind::KeySubstitutable.instantiate(base);
    let (pk, sk) = ks.generate_keypair(&mut rng).unwrap();
    let (ct, k) = ks.encapsulate(&pk, &mut rng).unwrap();
    let sk2 = substitute_secret_key(sk.expose());
    assert_ne!(ks.public_key_from_secret(&sk2).unwrap(), pk);
    assert!(ks.decapsulate(&sk2, &ct).unwrap().ct_eq(&k));
    // SenderKeyed: same key under two different honest keys.
    let sk_model = SenderKeyed::new(base);
    let (pa, sa) = sk_model.generate_keypair(&mut rng).unwrap();
    let (pb, sb) = sk_model.generate_keypair(&mut rng).unwrap();
    let x = [7u8; 32];
    let ca = sk_model.encapsulate_chosen(&pa, &x, &mut rng).unwrap();
    let cb = sk_model.encapsulate_chosen(&pb, &x, &mut rng).unwrap();
    assert!(
        sk_model
            .decapsulate(sa.expose(), &ca)
            .unwrap()
            .ct_eq(&sk_model.decapsulate(sb.expose(), &cb).unwrap())
    );
    // Real ML-KEM: a mauled ciphertext gives an unrelated key.
    let real = ModelKind::Real.instantiate(base);
    let (pk, sk) = real.generate_keypair(&mut rng).unwrap();
    let (ct, k) = real.encapsulate(&pk, &mut rng).unwrap();
    assert!(
        !real
            .decapsulate(sk.expose(), &flip_last(&ct))
            .unwrap()
            .ct_eq(&k)
    );
}

#[test]
fn vyra_assembly_over_real_components_is_vyra_kem_1() {
    let ctx = AttackContext::new(Scenario {
        combiner: CombinerKind::Vyra,
        first: ModelKind::Real,
        second: ModelKind::Real,
    });
    let named = HybridKem::new(KemSuite::Vyra1);
    let mut r1 = DeterministicEntropy::from_seed(b"same");
    let mut r2 = DeterministicEntropy::from_seed(b"same");
    let (pk1, sk1) = ctx.hybrid().generate_keypair(&mut r1).unwrap();
    let (pk2, _) = named.generate_keypair(&mut r2).unwrap();
    assert_eq!(pk1, pk2);
    let (ct1, k1) = ctx.hybrid().encapsulate(&pk1, &mut r1).unwrap();
    let (ct2, k2) = named.encapsulate(&pk2, &mut r2).unwrap();
    assert_eq!(ct1, ct2);
    assert!(k1.ct_eq(&k2));
    assert!(named.decapsulate(sk1.expose(), &ct1).unwrap().ct_eq(&k1));
}

#[test]
fn ind_cca2_oracle_refuses_only_the_challenge() {
    let ctx = AttackContext::new(Scenario {
        combiner: CombinerKind::Vyra,
        first: ModelKind::Real,
        second: ModelKind::Real,
    });
    let mut rng = DeterministicEntropy::from_seed(b"oracle");
    let (mut game, ch) = IndCca2Game::start(ctx.hybrid(), &mut rng).unwrap();
    assert!(matches!(
        game.decapsulate(&ch.ciphertext),
        OracleAnswer::Refused
    ));
    assert!(matches!(
        game.decapsulate(&flip_last(&ch.ciphertext)),
        OracleAnswer::Key(_)
    ));
    assert!(matches!(
        game.decapsulate(&[1, 2, 3]),
        OracleAnswer::Rejected
    ));
    assert_eq!(game.queries(), 3);
}

#[test]
fn binding_games_reject_trivial_claims() {
    let ctx = AttackContext::new(Scenario {
        combiner: CombinerKind::Naive,
        first: ModelKind::Constant,
        second: ModelKind::Constant,
    });
    let mut rng = DeterministicEntropy::from_seed(b"bind");
    // Same ciphertext twice under the same key pair: equal keys but Q equal.
    let (game, view) = HonestBindingGame::start(
        ctx.hybrid(),
        BindingModel::Hon,
        BindingTarget::Ciphertext,
        &mut rng,
    )
    .unwrap();
    assert!(view.leaked_secret_keys.is_none());
    let (ct, _) = ctx
        .hybrid()
        .encapsulate(&view.public_keys.0, &mut rng)
        .unwrap();
    assert!(!game.finish(&HonestBindingClaim {
        same_key_pair: true,
        ciphertexts: (ct.clone(), ct.clone()),
    }));
    // Malformed ciphertext counts as ⊥.
    let (game, _) = HonestBindingGame::start(
        ctx.hybrid(),
        BindingModel::Leak,
        BindingTarget::Ciphertext,
        &mut rng,
    )
    .unwrap();
    assert!(!game.finish(&HonestBindingClaim {
        same_key_pair: true,
        ciphertexts: (ct.clone(), vec![0u8; 3]),
    }));
    // MAL: identical secret keys cannot win K-PK.
    let (_, sk) = ctx.hybrid().generate_keypair(&mut rng).unwrap();
    let game = MaliciousBindingGame::new(ctx.hybrid(), BindingTarget::PublicKey);
    assert!(!game.finish(&MaliciousBindingClaim {
        secret_keys: (sk.clone(), sk),
        ciphertexts: (ct.clone(), ct),
    }));
    // HON start refuses MAL.
    assert!(
        HonestBindingGame::start(
            ctx.hybrid(),
            BindingModel::Mal,
            BindingTarget::PublicKey,
            &mut rng
        )
        .is_err()
    );
}
