//! P4: functional correctness of `SecretBytes::ct_eq`.
//!
//! NOT covered: timing / constant-time behaviour (bounded model checking says
//! nothing about it; it rests on the `subtle` crate and code inspection);
//! lengths beyond the bound; zeroization on drop (the harness skips `Drop`,
//! because zeroize's inline-assembly barrier is unsupported by Kani).

// Harness code: every index is checked by the model checker itself.
#![allow(clippy::indexing_slicing)]

use vyra_core::SecretBytes;

use crate::bounds::CT_EQ_MAX_LEN;

/// P4: for all byte strings `a`, `b` with lengths <= CT_EQ_MAX_LEN (chosen
/// independently, so unequal lengths are included) and all byte values,
/// `SecretBytes::ct_eq` returns without panicking and equals `a == b`.
#[kani::proof]
#[kani::unwind(10)]
fn secret_ct_eq_correct() {
    let abuf: [u8; CT_EQ_MAX_LEN] = kani::any();
    let bbuf: [u8; CT_EQ_MAX_LEN] = kani::any();
    let alen: usize = kani::any();
    let blen: usize = kani::any();
    kani::assume(alen <= CT_EQ_MAX_LEN);
    kani::assume(blen <= CT_EQ_MAX_LEN);
    let a = &abuf[..alen];
    let b = &bbuf[..blen];

    let sa = SecretBytes::from_slice(a);
    let sb = SecretBytes::from_slice(b);
    assert!(sa.ct_eq(&sb) == (a == b));
    assert!(sb.ct_eq(&sa) == (a == b));
    // Skip `Drop`: zeroize's optimisation barrier is inline assembly, which
    // Kani does not support. Zeroization is outside this property (see the
    // module docs) and is covered by vyra-core's host tests.
    core::mem::forget(sa);
    core::mem::forget(sb);
}
