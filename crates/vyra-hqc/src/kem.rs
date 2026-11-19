// Forked constant-time arithmetic indexes fixed-size buffers; see NOTICE.md
// ("Lints relaxed"). This in-source allow also overrides a command-line -D.
#![allow(clippy::indexing_slicing)]

/// HQC Key Encapsulation Mechanism with Fujisaki-Okamoto transform.
///
/// HQC v5.1 KEM (specification Section 3.7; reference tag `v5.1.0`,
/// `src/common/hqc-kem.c`):
/// - keygen: XOF(seed_kem || k/8) → seed_pke; pke_keygen(seed_pke);
///   ek = ek_pke, dk = seed_kem (compressed format, the v5.1 default)
/// - encaps: m, salt from RNG; H(ek), G(H||m||salt) → kk, theta; encrypt(ek, m, theta)
/// - decaps: XOF(dk || k/8) → seed_pke, sigma; re-derive (ek_pke, dk_pke);
///   decrypt → m'; re-encrypt; constant-time comparison; implicit rejection
use crate::params::{Buffer, HqcParams, SALT_BYTES, SEED_BYTES, SS_BYTES};
use crate::pke;
use crate::shake::{self, SeedExpander};
#[cfg(any(feature = "kgen", feature = "ecap"))]
use rand_core::CryptoRng;
use zeroize::Zeroize;

/// The KEM seed expander `XOF(seed_kem || k/8)` (v5.1 `xof_init_dom_sep`
/// with `PARAM_K` as domain separator).
#[cfg(any(feature = "kgen", feature = "dcap"))]
fn kem_seed_expander<P: HqcParams>(seed_kem: &[u8]) -> SeedExpander {
    let p = P::params();
    // k is 16, 24 or 32: the conversion cannot truncate.
    SeedExpander::new_with_domain(seed_kem, p.k as u8)
}

/// Deterministic KEM key generation from a 32-byte seed.
///
/// Returns (pk_bytes, sk_bytes) where:
/// - pk = ek_pke (seed_pke_ek || s_bytes)
/// - sk = seed_kem (v5.1 compressed `dk_KEM`)
#[cfg(feature = "kgen")]
pub(crate) fn keygen_deterministic<P: HqcParams>(
    seed_kem: &[u8; SEED_BYTES],
) -> (P::PkBuf, P::SkBuf) {
    // XOF(seed_kem || k/8) → seed_pke
    let mut ctx_kem = kem_seed_expander::<P>(seed_kem);
    let mut seed_pke = [0u8; SEED_BYTES];
    ctx_kem.get_bytes(&mut seed_pke);

    // PKE keygen
    let (ek_pke, mut dk_pke) = pke::pke_keygen::<P>(&seed_pke);

    // Zeroize intermediates — dk_pke is re-derived from seed_kem on use
    seed_pke.zeroize();
    dk_pke.zeroize();

    // sk = seed_kem
    let mut sk = P::SkBuf::zeroed();
    sk.as_mut().copy_from_slice(seed_kem);

    (ek_pke, sk)
}

/// KEM key generation.
///
/// Samples a random seed, then delegates to [`keygen_deterministic`].
#[cfg(feature = "kgen")]
pub(crate) fn keygen<P: HqcParams>(rng: &mut impl CryptoRng) -> (P::PkBuf, P::SkBuf) {
    let mut seed_kem = [0u8; SEED_BYTES];
    rng.fill_bytes(&mut seed_kem);
    let result = keygen_deterministic::<P>(&seed_kem);
    seed_kem.zeroize();
    result
}

/// Deterministic KEM encapsulation from a message and salt.
///
/// Returns (shared_secret, ciphertext).
#[cfg(feature = "ecap")]
pub(crate) fn encaps_deterministic<P: HqcParams>(
    ek_kem: &[u8],
    m: &[u8],
    salt: &[u8; SALT_BYTES],
) -> ([u8; SS_BYTES], P::CtBuf) {
    let p = P::params();

    // H(ek_kem || 0x01) → 32-byte hash of public key
    let tmp_h = shake::hash_h(ek_kem);

    // G(H || m || salt || 0x00) → 64 bytes: kk || theta
    let mut tmp_g = shake::hash_g(&[&tmp_h, m, salt]);

    let mut kk = [0u8; SS_BYTES];
    kk.copy_from_slice(&tmp_g[..SS_BYTES]);
    let mut theta = [0u8; SS_BYTES];
    theta.copy_from_slice(&tmp_g[SS_BYTES..2 * SS_BYTES]);

    // Encrypt
    let c_pke = pke::pke_encrypt::<P>(ek_kem, m, &theta);

    // Zeroize intermediates
    tmp_g.zeroize();
    theta.zeroize();

    // Ciphertext = c_pke || salt
    let mut ct = P::CtBuf::zeroed();
    {
        let ct = ct.as_mut();
        ct[..p.ct_bytes - SALT_BYTES].copy_from_slice(c_pke.as_ref());
        ct[p.ct_bytes - SALT_BYTES..].copy_from_slice(salt);
    }

    (kk, ct)
}

/// KEM encapsulation.
///
/// Samples random message and salt, then delegates to [`encaps_deterministic`].
#[cfg(feature = "ecap")]
pub(crate) fn encaps<P: HqcParams>(
    ek_kem: &[u8],
    rng: &mut (impl CryptoRng + ?Sized),
) -> ([u8; SS_BYTES], P::CtBuf) {
    let mut m = P::KBuf::zeroed();
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(m.as_mut());
    rng.fill_bytes(&mut salt);
    let result = encaps_deterministic::<P>(ek_kem, m.as_ref(), &salt);
    m.as_mut().zeroize();
    salt.zeroize();
    result
}

/// KEM decapsulation with implicit rejection.
///
/// `dk_kem` is the v5.1 compressed decapsulation key `seed_kem`; the PKE key
/// pair and `sigma` are re-derived from it exactly as the reference does.
/// Returns shared secret (SS_BYTES).
#[cfg(feature = "dcap")]
pub(crate) fn decaps<P: HqcParams>(dk_kem: &[u8], c_kem: &[u8]) -> [u8; SS_BYTES] {
    decaps_with_ek::<P>(dk_kem, c_kem).0
}

/// KEM decapsulation that also returns the encapsulation key `ek_PKE` it
/// re-derived from `dk_kem` (computed once, in step 5 of the specification's
/// `HQC-KEM.Decaps`). The shared secret is computed exactly as by [`decaps`].
#[cfg(feature = "dcap")]
pub(crate) fn decaps_with_ek<P: HqcParams>(
    dk_kem: &[u8],
    c_kem: &[u8],
) -> ([u8; SS_BYTES], P::PkBuf) {
    let p = P::params();

    // Re-derive seed_pke and sigma: XOF(seed_kem || k/8) → seed_pke || sigma
    let mut ctx_kem = kem_seed_expander::<P>(&dk_kem[..SEED_BYTES]);
    let mut seed_pke = [0u8; SEED_BYTES];
    let mut sigma = P::KBuf::zeroed();
    ctx_kem.get_bytes(&mut seed_pke);
    ctx_kem.get_bytes(sigma.as_mut());

    // Re-derive the PKE key pair (ek_pke, dk_pke)
    let (ek_pke, mut dk_pke) = pke::pke_keygen::<P>(&seed_pke);
    seed_pke.zeroize();
    let ek_kem = ek_pke.as_ref();
    let sigma_bytes = sigma.as_ref();

    // Parse ciphertext: c_pke || salt
    let c_pke_len = p.n_bytes + p.n1n2_bytes;
    let c_pke = &c_kem[..c_pke_len];
    let salt = &c_kem[c_pke_len..c_pke_len + SALT_BYTES];

    // Decrypt
    let mut m_prime = pke::pke_decrypt::<P>(&dk_pke, c_pke);
    dk_pke.zeroize();

    // Re-derive theta
    let tmp_h = shake::hash_h(ek_kem);

    // G(H || m' || salt || 0x00) → 64 bytes: kk' || theta'
    let mut tmp_g = shake::hash_g(&[&tmp_h, m_prime.as_ref(), salt]);

    let kk_prime = &tmp_g[..SS_BYTES];
    let theta_prime = &tmp_g[SS_BYTES..2 * SS_BYTES];

    // Re-encrypt
    let c_pke_prime = pke::pke_encrypt::<P>(ek_kem, m_prime.as_ref(), theta_prime);

    // Zeroize decrypted message — no longer needed
    m_prime.as_mut().zeroize();

    // J function for rejection key: SHA3-256(H || sigma || c_kem || 0x03)
    let mut k_rej = shake::hash_j(&[&tmp_h, sigma_bytes, c_kem]);

    // Constant-time comparison of ciphertexts (the received salt is compared
    // against its own copy implicitly and is always equal, so comparing the
    // c_pke halves is output-identical to comparing full ciphertexts).
    let equal = {
        use ctutils::CtEq;
        c_pke.ct_eq(c_pke_prime.as_ref())
    };

    // Implicit rejection: k_rej unless the re-encryption matched, selected
    // per byte in constant time.
    let mut ss = [0u8; SS_BYTES];
    for i in 0..SS_BYTES {
        use ctutils::CtSelect;
        ss[i] = k_rej[i].ct_select(&kk_prime[i], equal);
    }

    // Zeroize remaining sensitive intermediates (c_pke_prime derives from the
    // secret m' whenever the FO comparison fails).
    let mut c_pke_prime = c_pke_prime;
    c_pke_prime.as_mut().zeroize();
    tmp_g.zeroize();
    k_rej.zeroize();
    sigma.as_mut().zeroize();

    (ss, ek_pke)
}
