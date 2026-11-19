//! GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
//!
//! Primitive element (alpha) = 0x03.
//!
//! HQC v5.1 change (specification changelog; reference tag `v5.1.0`,
//! `src/ref/gf.{c,h}`, `PARAM_GF_POLY 0x11B`, `gf_alpha 0x03`): the previous
//! version used 0x11D with alpha = 2. With 0x11B the element 2 is not
//! primitive, hence alpha = 3.

/// Irreducible polynomial of GF(2^8) used by HQC v5.1.
const GF_POLY: u16 = 0x11B;

/// Powers of alpha = 3: `GF_EXP[i] = alpha^i` (v5.1 reference `gf_exp`).
/// Extended to 258 entries like the reference table. Only ever indexed by
/// public values (exponents derived from loop counters).
pub(crate) static GF_EXP: [u16; 258] = [
    1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115,
    149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
    112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208,
    107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240,
    11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174,
    233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195,
    94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
    239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
    234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176,
    203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54,
    90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151,
    162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 3, 5,
];

/// Constant-time GF(2^8) multiplication.
///
/// Uses bitwise carry-less multiplication with modular reduction by 0x11B.
#[inline]
pub(crate) fn gf_mul(a: u16, b: u16) -> u16 {
    let mut a = a;
    let mut r = a & (0u16.wrapping_sub(b & 1));
    for i in 1..8 {
        a = (a << 1) ^ ((0u16.wrapping_sub(a >> 7)) & GF_POLY);
        r ^= a & (0u16.wrapping_sub((b >> i) & 1));
    }
    r
}

/// GF(2^8) squaring: returns a^2.
#[inline]
pub(crate) fn gf_square(a: u16) -> u16 {
    gf_mul(a, a)
}

/// GF(2^8) multiplicative inverse via the addition chain 1,2,3,4,7,11,15,30,60,120,127,254.
///
/// Returns 0 if a = 0.
#[inline]
pub(crate) fn gf_inverse(a: u16) -> u16 {
    let inv = gf_square(a); // a^2
    let tmp1 = gf_mul(inv, a); // a^3
    let inv = gf_square(inv); // a^4
    let tmp2 = gf_mul(inv, tmp1); // a^7
    let tmp1 = gf_mul(inv, tmp2); // a^11
    let mut inv = gf_mul(tmp1, inv); // a^15
    inv = gf_square(inv); // a^30
    inv = gf_square(inv); // a^60
    inv = gf_square(inv); // a^120
    inv = gf_mul(inv, tmp2); // a^127
    inv = gf_square(inv); // a^254
    inv
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Schoolbook product modulo 0x11B, written independently of `gf_mul`.
    fn slow_mul(a: u16, b: u16) -> u16 {
        let mut r: u32 = 0;
        for i in 0..8 {
            if (b >> i) & 1 == 1 {
                r ^= u32::from(a) << i;
            }
        }
        for i in (8..15).rev() {
            if (r >> i) & 1 == 1 {
                r ^= u32::from(GF_POLY) << (i - 8);
            }
        }
        r as u16
    }

    #[test]
    fn mul_matches_schoolbook() {
        for a in 0..256u16 {
            for b in 0..256u16 {
                assert_eq!(gf_mul(a, b), slow_mul(a, b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn exp_table_is_powers_of_alpha_3() {
        let mut e = 1u16;
        for (i, &v) in GF_EXP.iter().enumerate() {
            assert_eq!(v, e, "alpha^{i}");
            e = gf_mul(e, 3);
        }
        // alpha has order 255: all 255 powers are distinct.
        let mut seen = [false; 256];
        for &v in &GF_EXP[..255] {
            assert!(!seen[v as usize]);
            seen[v as usize] = true;
        }
    }

    #[test]
    fn inverse_is_inverse() {
        assert_eq!(gf_inverse(0), 0);
        for a in 1..256u16 {
            assert_eq!(gf_mul(a, gf_inverse(a)), 1, "{a}");
        }
    }
}
