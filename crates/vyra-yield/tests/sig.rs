//! Signature side: equivalence of the `Vyra` assembly with the named suites,
//! the failure models, and the matrix at small N (controls and the expected
//! pattern). Observed attack outcomes for the implemented adversaries only;
//! not security proofs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::OnceLock;

use vyra_core::{DeterministicEntropy, SignatureScheme};
use vyra_sig::{
    CompositeComponent, CompositeSignature, CustomComposite, CustomSuite, Ed25519, MlDsa44,
    SigSuite, SlhDsaShake128s, composite_context, message_representative,
};
use vyra_yield::scenario::Side;
use vyra_yield::sig::adversaries::{SigAdversary, StandaloneMode};
use vyra_yield::sig::compositions::{CompositionKind, VYRA_ID};
use vyra_yield::sig::controls::{evaluate_sig_claims, evaluate_sig_controls};
use vyra_yield::sig::experiment::{SigCellResult, run_sig_matrix};
use vyra_yield::sig::games::SigGame;
use vyra_yield::sig::models::forgeable::forge;
use vyra_yield::sig::models::key_substitutable::substitute_public_key;
use vyra_yield::sig::models::malleable::maul;
use vyra_yield::sig::models::{SigBase, SigModel, derive_public_key};
use vyra_yield::sig::{SigContext, SigPair, SigScenario};
use vyra_yield::stats::Verdict;

const M: &[u8] = b"equivalence message";
const CTX: &[u8] = b"equivalence ctx";

/// Components over `M'(id)`, signed by hand with the given randomness.
fn by_hand(
    first: &dyn CompositeComponent,
    second: &dyn CompositeComponent,
    id: u8,
    pk: &[u8],
    sk: &[u8],
    rng_seed: &[u8],
) -> Vec<u8> {
    let (pk1, pk2) = pk.split_at(first.public_key_len());
    let (sk1, sk2) = sk.split_at(first.secret_key_len());
    let (m, cctx) = CompositionKind::Vyra
        .signed_input(id, pk1, pk2, M, CTX)
        .unwrap();
    assert_eq!(cctx, composite_context(id).to_vec());
    let mut rng = DeterministicEntropy::from_seed(rng_seed);
    let mut sig = first.sign_half(sk1, &m, &cctx, &mut rng).unwrap();
    sig.extend(second.sign_half(sk2, &m, &cctx, &mut rng).unwrap());
    sig
}

/// The custom `Vyra` assembly and the named suite are the same engine: both
/// produce exactly "components over M'(id)" for their id, from identical keys.
fn equivalence(
    suite: SigSuite,
    first: Box<dyn CompositeComponent>,
    second: Box<dyn CompositeComponent>,
) {
    let f = suite.first();
    let s = suite.second();
    let named = CompositeSignature::new(suite);
    let custom = CustomComposite::from_components(
        CustomSuite {
            id: VYRA_ID,
            name: "eq",
            level: suite.level(),
        },
        first,
        second,
    )
    .unwrap();
    let (pk, sk) = named
        .generate_raw(&mut DeterministicEntropy::from_seed(b"keys"))
        .unwrap();
    let (pk_c, sk_c) = custom
        .generate_raw(&mut DeterministicEntropy::from_seed(b"keys"))
        .unwrap();
    assert_eq!(pk, pk_c);
    assert!(sk.ct_eq(&sk_c));
    // Our encoding of M' equals vyra-sig's for the named suite.
    let (pk1, pk2) = pk.split_at(f.public_key_len());
    assert_eq!(
        CompositionKind::Vyra
            .signed_input(suite.id(), pk1, pk2, M, CTX)
            .unwrap()
            .0,
        message_representative(suite, &pk, CTX, M).unwrap()
    );
    let sig_named = named
        .sign_raw(
            sk.expose(),
            M,
            CTX,
            &mut DeterministicEntropy::from_seed(b"sig"),
        )
        .unwrap();
    let sig_custom = custom
        .sign_raw(
            sk.expose(),
            M,
            CTX,
            &mut DeterministicEntropy::from_seed(b"sig"),
        )
        .unwrap();
    assert_eq!(
        sig_named,
        by_hand(f, s, suite.id(), &pk, sk.expose(), b"sig")
    );
    assert_eq!(sig_custom, by_hand(f, s, VYRA_ID, &pk, sk.expose(), b"sig"));
    named.verify_raw(&pk, M, CTX, &sig_named).unwrap();
    custom.verify_raw(&pk, M, CTX, &sig_custom).unwrap();
    // Only the suite byte differs: neither verifies the other's signature.
    assert!(named.verify_raw(&pk, M, CTX, &sig_custom).is_err());
    assert!(custom.verify_raw(&pk, M, CTX, &sig_named).is_err());
}

#[test]
fn vyra_assembly_equals_named_transition_suite() {
    equivalence(SigSuite::Vyra2, Box::new(MlDsa44), Box::new(Ed25519));
}

#[test]
fn vyra_assembly_equals_named_dual_pq_suite() {
    equivalence(SigSuite::Pq1, Box::new(MlDsa44), Box::new(SlhDsaShake128s));
}

#[test]
fn models_keep_correctness_and_break_what_they_say() {
    for base in [SigBase::MlDsa44, SigBase::Ed25519] {
        for model in SigModel::ALL {
            let c = model.instantiate(base);
            let mut rng = DeterministicEntropy::from_seed(model.name().as_bytes());
            let (pk, sk) = c.generate_keypair(&mut rng).unwrap();
            assert_eq!(derive_public_key(c.as_ref(), sk.expose()).unwrap(), pk);
            c.validate_public_key(&pk).unwrap();
            let sig = c.sign_half(sk.expose(), M, CTX, &mut rng).unwrap();
            c.verify_half(&pk, M, CTX, &sig).unwrap();
            let s2 = SignatureScheme::sign(c.as_ref(), sk.expose(), M, &mut rng).unwrap();
            SignatureScheme::verify(c.as_ref(), &pk, M, &s2).unwrap();
            match model {
                SigModel::Forgeable => {
                    let f = forge(&pk, CTX, b"other", c.signature_len());
                    c.verify_half(&pk, b"other", CTX, &f).unwrap();
                }
                SigModel::Malleable => c.verify_half(&pk, M, CTX, &maul(&sig)).unwrap(),
                SigModel::KeySubstitutable => {
                    let pk2 = substitute_public_key(&pk);
                    assert_ne!(pk2, pk);
                    c.verify_half(&pk2, M, CTX, &sig).unwrap();
                }
                SigModel::ContextIgnoring => {
                    // The half is a valid standalone empty-context signature.
                    SignatureScheme::verify(c.as_ref(), &pk, M, &sig).unwrap();
                }
                SigModel::MessageCollapsing | SigModel::Real => {
                    assert!(c.verify_half(&pk, b"other", CTX, &sig).is_err());
                }
            }
        }
    }
}

#[test]
fn every_composition_round_trips_with_real_components() {
    for composition in CompositionKind::ALL {
        let ctx = SigContext::new(SigScenario {
            composition,
            pair: SigPair::Transition,
            first: SigModel::Real,
            second: SigModel::Real,
        })
        .unwrap();
        let mut rng = DeterministicEntropy::from_seed(composition.name().as_bytes());
        let (pk, sk) = ctx.composite().generate(&mut rng).unwrap();
        let sig = ctx.composite().sign(sk.expose(), M, CTX, &mut rng).unwrap();
        assert!(ctx.composite().verify(&pk, M, CTX, &sig), "{composition:?}");
        assert!(!ctx.composite().verify(&pk, b"other", CTX, &sig));
        let _ = ctx.component(Side::First).name();
    }
}

const TRIALS: u64 = 8;
const PQ_TRIALS: u64 = 1;
const SEED: &str = "vyra-yield-sig-test";

fn results() -> &'static [SigCellResult] {
    static CELL: OnceLock<Vec<SigCellResult>> = OnceLock::new();
    CELL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        run_sig_matrix(SEED, TRIALS, PQ_TRIALS, threads).expect("sig matrix runs")
    })
}

fn verdict(
    composition: CompositionKind,
    pair: SigPair,
    first: SigModel,
    second: SigModel,
    game: SigGame,
    adversary: SigAdversary,
) -> Verdict {
    results()
        .iter()
        .find(|r| {
            r.spec.scenario
                == SigScenario {
                    composition,
                    pair,
                    first,
                    second,
                }
                && r.spec.game == game
                && r.spec.adversary == adversary
        })
        .map(|r| r.estimate.verdict)
        .expect("cell exists")
}

#[test]
fn every_sig_control_passes() {
    for c in evaluate_sig_controls(results()) {
        assert!(c.passed, "control {} failed: {:?}", c.id, c.mismatches);
    }
}

#[test]
fn every_sig_claim_check_passes() {
    for c in evaluate_sig_claims(results()) {
        assert!(c.passed, "claim {} failed: {:?}", c.id, c.mismatches);
    }
}

#[test]
fn named_controls() {
    use CompositionKind::*;
    use SigModel::*;
    let t = SigPair::Transition;
    // Either with one Forgeable component is forgeable.
    assert_eq!(
        verdict(
            Either,
            t,
            Forgeable,
            Real,
            SigGame::EufCma,
            SigAdversary::Forge
        ),
        Verdict::Broken
    );
    // Concat halves strip; ConcatCtx halves splice across signers.
    assert_eq!(
        verdict(
            Concat,
            t,
            Real,
            Real,
            SigGame::StripComposite,
            SigAdversary::StripHalf(Side::First)
        ),
        Verdict::Broken
    );
    assert_eq!(
        verdict(
            ConcatCtx,
            t,
            Real,
            Real,
            SigGame::Mix,
            SigAdversary::MixHalves
        ),
        Verdict::Broken
    );
    // Since vyra-sig U12-R1: no Vyra half strips; the pre-fix PureEd25519
    // half (VyraPureEd) still does.
    for side in Side::BOTH {
        assert_eq!(
            verdict(
                Vyra,
                t,
                Real,
                Real,
                SigGame::StripComposite,
                SigAdversary::StripHalf(side)
            ),
            Verdict::NoAttackFound
        );
    }
    assert_eq!(
        verdict(
            VyraPureEd,
            t,
            Real,
            Real,
            SigGame::StripComposite,
            SigAdversary::StripHalf(Side::Second)
        ),
        Verdict::Broken
    );
}

#[test]
fn key_reuse_before_and_after_u12_r1() {
    use CompositionKind::*;
    use SigModel::*;
    // Regression control S-E: the U11-S finding, on the pre-fix design.
    assert_eq!(
        verdict(
            VyraPureEd,
            SigPair::Transition,
            Forgeable,
            Real,
            SigGame::StripStandalone,
            SigAdversary::Recombine(StandaloneMode::Default)
        ),
        Verdict::Broken
    );
    // The claim after the fix: no standalone oracle mode completes a Vyra
    // composite when one component is forgeable, in either pair.
    for pair in [SigPair::Transition, SigPair::DualPq] {
        for (a, b) in [(Forgeable, Real), (Real, Forgeable)] {
            for mode in StandaloneMode::ALL {
                assert_eq!(
                    verdict(
                        Vyra,
                        pair,
                        a,
                        b,
                        SigGame::StripStandalone,
                        SigAdversary::Recombine(mode)
                    ),
                    Verdict::NoAttackFound,
                    "{pair:?} {a:?}x{b:?} {mode:?}"
                );
            }
            assert_eq!(
                verdict(Vyra, pair, a, b, SigGame::EufCma, SigAdversary::Forge),
                Verdict::NoAttackFound
            );
        }
    }
}
