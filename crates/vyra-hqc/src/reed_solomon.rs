// Index loops mirror the reference C code line by line (loop bounds are
// public). Indexing of fixed-size buffers: see NOTICE.md ("Lints relaxed");
// this in-source allow also overrides a command-line -D.
#![allow(clippy::needless_range_loop, clippy::indexing_slicing)]

/// Reed-Solomon encoding and decoding over GF(2^8).
///
/// Systematic shortened RS(n1, k) with error correction capability
/// delta = t = (n1-k)/2. Generator polynomial roots: alpha^1, ..., alpha^(2t)
/// with alpha = 0x03 in GF(2^8) = F2[X]/(X^8 + X^4 + X^3 + X + 1).
///
/// Decoding follows the HQC v5.1 reference implementation (tag `v5.1.0`,
/// `src/ref/reed_solomon.c`, "Improve RS decoding performance"): syndromes,
/// constant-time Berlekamp error-locator computation, error-locator evaluation
/// at the k message positions only, and Forney error values via `z(x)` and the
/// odd part of `sigma(x)` with a batched inversion. It replaces the additive-FFT
/// root finding of the previous version, which was specific to the old field
/// polynomial. The constant-time structure (mask-based selection, loop bounds
/// depending only on public parameters) is the reference's.
use crate::gf256::{GF_EXP, gf_inverse, gf_mul};
use crate::params::{HqcParameters, MAX_DELTA, MAX_K, MAX_N1};
use zeroize::Zeroize;

/// Encode message into RS codeword (systematic).
///
/// Message bytes are placed at positions [n1-k..n1-1] (high end).
/// Parity bytes at positions [0..n1-k-1] (low end).
pub(crate) fn reed_solomon_encode(cdw: &mut [u8], msg: &[u8], p: &HqcParameters) {
    // Clear output
    cdw[..p.n1].fill(0);

    for i in 0..p.k {
        let gate_value = msg[p.k - 1 - i] ^ cdw[p.n1 - p.k - 1];

        // Shift register: shift right by 1 and XOR with gate_value * g[k]
        for k_idx in (1..p.n1 - p.k).rev() {
            cdw[k_idx] =
                cdw[k_idx - 1] ^ (gf_mul(gate_value as u16, p.rs_poly[k_idx] as u16) as u8);
        }
        cdw[0] = gf_mul(gate_value as u16, p.rs_poly[0] as u16) as u8;
    }

    // Copy message to high positions
    cdw[p.n1 - p.k..p.n1].copy_from_slice(&msg[..p.k]);
}

/// 0xFFFF if `x != 0`, else 0 (reference `make_nonzero_mask`; the result is
/// passed through an optimisation barrier like the reference's `CT_OPAQUE`).
#[inline]
fn nonzero_mask(x: u16) -> u16 {
    core::hint::black_box(0u16.wrapping_sub((x | x.wrapping_neg()) >> 15))
}

/// 1 if `x == 0`, else 0 (reference `is_zero`).
#[inline]
fn is_zero(x: u8) -> u8 {
    let mut t = x as u16;
    t |= t.wrapping_neg();
    core::hint::black_box(((t >> 8) ^ 1) & 1) as u8
}

/// `alpha^e` for a public exponent `e`.
#[inline]
fn alpha_pow(e: usize) -> u16 {
    GF_EXP[e % 255]
}

/// Exponent `e_beta` of the evaluation point `beta = alpha^(-pos)` of message
/// position `i_msg`, where `pos = n1 - k + i_msg` is its codeword position
/// (reference `eval_alpha_pow` table definition, `tools/rs/constants.c`).
#[inline]
fn beta_exponent(i_msg: usize, p: &HqcParameters) -> usize {
    (255 - (p.n1 - p.k + i_msg) % 255) % 255
}

/// Compute 2*delta syndromes: `S_i = sum_j cdw[j] * alpha^((i+1) j)`.
fn compute_syndromes(syndromes: &mut [u16], cdw: &[u8], p: &HqcParameters) {
    for i in 0..(2 * p.delta) {
        syndromes[i] = 0;
        for j in 1..p.n1 {
            syndromes[i] ^= gf_mul(cdw[j] as u16, alpha_pow((i + 1) * j));
        }
        syndromes[i] ^= cdw[0] as u16;
    }
}

/// Berlekamp algorithm: compute the error locator polynomial sigma
/// (reference `compute_error_locator_polynomial`, constant time).
fn compute_error_locator_polynomial(sigma: &mut [u16], syndromes: &[u16], p: &HqcParameters) {
    let t = p.delta;
    let mut deg_sigma: u16 = 0;
    let mut sigma_mu = [0u16; MAX_DELTA + 1];
    let mut x_sigma_rho = [0u16; MAX_DELTA + 1];
    x_sigma_rho[1] = 1;
    let mut deg_sigma_rho: u16 = 0;
    let mut rho: u16 = u16::MAX; // -1
    let mut d_rho: u16 = 1;
    let mut d_mu: u16 = syndromes[0];

    sigma[0] = 1;
    for mu in 0..(2 * t) {
        let mu16 = mu as u16;
        // 0xFFFF if d_mu != 0
        let d_nonzero_mask = 0u16.wrapping_sub(d_mu.wrapping_neg() >> 15);

        sigma_mu[..=t].copy_from_slice(&sigma[..=t]);
        let deg_sigma_mu = deg_sigma;

        let d_mu_over_d_rho = gf_mul(d_mu, gf_inverse(d_rho));
        for i in 1..=(mu + 1).min(t) {
            sigma[i] ^= gf_mul(d_mu_over_d_rho, x_sigma_rho[i]);
        }

        let deg_x_sigma_rho = mu16.wrapping_sub(rho).wrapping_add(deg_sigma_rho);

        // 0xFFFF if deg_x_sigma_rho > deg_sigma_mu
        let deg_would_grow_mask =
            0u16.wrapping_sub(deg_sigma_mu.wrapping_sub(deg_x_sigma_rho) >> 15);

        let promote_mask = core::hint::black_box(d_nonzero_mask & deg_would_grow_mask);

        deg_sigma ^= promote_mask & (deg_x_sigma_rho ^ deg_sigma);

        for i in (1..=t).rev() {
            x_sigma_rho[i] =
                (promote_mask & sigma_mu[i - 1]) ^ (!promote_mask & x_sigma_rho[i - 1]);
        }
        deg_sigma_rho ^= promote_mask & (deg_sigma_mu ^ deg_sigma_rho);
        rho ^= promote_mask & (mu16 ^ rho);
        d_rho ^= promote_mask & (d_mu ^ d_rho);

        if mu + 1 < 2 * t {
            d_mu = syndromes[mu + 1];
            for i in 1..=(mu + 1).min(t) {
                d_mu ^= gf_mul(sigma[i], syndromes[mu + 1 - i]);
            }
        }
    }

    sigma_mu.zeroize();
    x_sigma_rho.zeroize();
}

/// `poly(beta)` for the evaluation point `beta` of message position `i_msg`:
/// `poly[0] + sum_{j=1..t} poly[j] * beta^j` (reference
/// `evaluate_poly_at_powers` with the `eval_alpha_pow` row of `i_msg`).
#[inline]
fn evaluate_at_message_position(poly: &[u16], i_msg: usize, p: &HqcParameters) -> u16 {
    let e_beta = beta_exponent(i_msg, p);
    let mut out = poly[0];
    for j in 1..=p.delta {
        out ^= gf_mul(poly[j], alpha_pow(e_beta * j));
    }
    out
}

/// Mark the message positions that are roots of sigma (reference
/// `compute_error_positions`).
fn compute_error_positions(error_positions: &mut [u8], sigma: &[u16], p: &HqcParameters) {
    for i in 0..p.k {
        let val = evaluate_at_message_position(sigma, i, p);
        error_positions[i] = is_zero((val & 0xFF) as u8);
    }
}

/// Batched inversion over the k message positions; zero inputs are treated
/// as one so that one inversion serves all (reference `batch_inverse`).
fn batch_inverse(inv: &mut [u8], a: &[u8], k: usize) {
    let mut prefix = [0u8; MAX_K];
    let mut acc: u8 = 1;

    for i in 0..k {
        let safe_a = a[i] | is_zero(a[i]);
        prefix[i] = acc;
        acc = gf_mul(acc as u16, safe_a as u16) as u8;
    }

    let inv_all = gf_inverse(acc as u16) as u8;
    let mut suffix: u8 = 1;
    for i in (0..k).rev() {
        let safe_a = a[i] | is_zero(a[i]);
        let prod_except_i = gf_mul(prefix[i] as u16, suffix as u16) as u8;
        inv[i] = gf_mul(prod_except_i as u16, inv_all as u16) as u8;
        suffix = gf_mul(suffix as u16, safe_a as u16) as u8;
    }

    prefix.zeroize();
}

/// Forney error values at the message positions and correction of the
/// message part (reference `correct_errors`).
fn correct_errors(
    message: &mut [u8],
    cdw: &[u8],
    syndromes: &[u16],
    sigma: &[u16],
    error_positions: &[u8],
    p: &HqcParameters,
) {
    let t = p.delta;
    let mut z = [0u16; MAX_DELTA + 1];
    z[0] = 1;
    for i in 0..t {
        z[i + 1] = syndromes[i];
        for j in 0..i {
            z[i + 1] ^= gf_mul(sigma[j + 1], syndromes[i - 1 - j]);
        }
        z[i + 1] ^= sigma[i + 1];
    }

    let mut sigma_odd = [0u16; MAX_DELTA + 1];
    for i in (1..=t).step_by(2) {
        sigma_odd[i] = sigma[i];
    }

    let mut numerator = [0u8; MAX_K];
    let mut denominator = [0u8; MAX_K];
    for i in 0..p.k {
        numerator[i] = evaluate_at_message_position(&z, i, p) as u8;
        denominator[i] = evaluate_at_message_position(&sigma_odd, i, p) as u8;
    }

    let mut inverse_denominator = [0u8; MAX_K];
    batch_inverse(&mut inverse_denominator, &denominator, p.k);

    for i in 0..p.k {
        let has_error = nonzero_mask(error_positions[i] as u16);
        let den_nonzero = nonzero_mask(denominator[i] as u16);
        let valid = has_error & den_nonzero;

        let mag = gf_mul(numerator[i] as u16, inverse_denominator[i] as u16);
        let corr = (valid & mag) as u8;
        message[i] = cdw[i + (p.n1 - p.k)] ^ corr;
    }

    z.zeroize();
    sigma_odd.zeroize();
    numerator.zeroize();
    denominator.zeroize();
    inverse_denominator.zeroize();
}

/// Decode RS codeword, correcting up to delta errors in the message part.
///
/// Writes the k message bytes to `msg`.
pub(crate) fn reed_solomon_decode(msg: &mut [u8], cdw: &[u8], p: &HqcParameters) {
    let mut cdw_bytes = [0u8; MAX_N1];
    let mut syndromes = [0u16; 2 * MAX_DELTA];
    let mut sigma = [0u16; MAX_DELTA + 1];
    let mut error_positions = [0u8; MAX_K];
    let mut message = [0u8; MAX_K];

    cdw_bytes[..p.n1].copy_from_slice(&cdw[..p.n1]);

    compute_syndromes(&mut syndromes, &cdw_bytes, p);
    compute_error_locator_polynomial(&mut sigma, &syndromes, p);
    compute_error_positions(&mut error_positions, &sigma, p);
    correct_errors(
        &mut message,
        &cdw_bytes,
        &syndromes,
        &sigma,
        &error_positions,
        p,
    );

    msg[..p.k].copy_from_slice(&message[..p.k]);

    cdw_bytes.zeroize();
    syndromes.zeroize();
    sigma.zeroize();
    error_positions.zeroize();
    message.zeroize();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::params::{HQC_128, HQC_192, HQC_256};
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Official RS test vectors of the v5.1.0 reference (`kats/rs/hqc-*/rs.tv`,
    /// first 25 samples of each of the 8 scenarios): encoding reproduces the
    /// codeword and decoding of the corrupted word reproduces the reference
    /// decoder's output, including the scenarios beyond the correction
    /// capability, where only an exact port gives the same bytes.
    fn check_vectors(data: &str, p: &HqcParameters) -> usize {
        let mut n = 0;
        for line in data.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            assert_eq!(f.len(), 5, "{line}");
            let (scenario, msg, cdw, corrupted, decoded) =
                (f[0], unhex(f[1]), unhex(f[2]), unhex(f[3]), unhex(f[4]));
            assert_eq!(msg.len(), p.k);
            assert_eq!(cdw.len(), p.n1);
            let mut enc = [0u8; MAX_N1];
            reed_solomon_encode(&mut enc, &msg, p);
            assert_eq!(&enc[..p.n1], cdw.as_slice(), "encode {scenario} #{n}");
            let mut out = [0u8; MAX_K];
            reed_solomon_decode(&mut out, &corrupted, p);
            assert_eq!(&out[..p.k], decoded.as_slice(), "decode {scenario} #{n}");
            n += 1;
        }
        n
    }

    #[test]
    fn official_rs_vectors_hqc1() {
        let n = check_vectors(
            include_str!("../tests/data/rs/hqc-1-rs-subset.txt"),
            &HQC_128,
        );
        assert_eq!(n, 200);
    }

    #[test]
    fn official_rs_vectors_hqc3() {
        let n = check_vectors(
            include_str!("../tests/data/rs/hqc-3-rs-subset.txt"),
            &HQC_192,
        );
        assert_eq!(n, 200);
    }

    #[test]
    fn official_rs_vectors_hqc5() {
        let n = check_vectors(
            include_str!("../tests/data/rs/hqc-5-rs-subset.txt"),
            &HQC_256,
        );
        assert_eq!(n, 200);
    }

    /// The generator polynomials in `params` are (X + alpha)...(X + alpha^2t).
    #[test]
    fn generator_polynomials_have_the_specified_roots() {
        for p in [&HQC_128, &HQC_192, &HQC_256] {
            assert_eq!(p.rs_poly.len(), 2 * p.delta + 1);
            for r in 1..=2 * p.delta {
                let x = alpha_pow(r);
                let mut acc = 0u16;
                for &c in p.rs_poly.iter().rev() {
                    acc = gf_mul(acc, x) ^ c as u16;
                }
                assert_eq!(acc, 0, "root alpha^{r}");
            }
        }
    }
}
