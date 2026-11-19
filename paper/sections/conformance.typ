#import "common.typ": *

= Component conformance and the HQC v5.1 port <sec-conf>

This section is supporting engineering. The experiment measures the composition; it is only
meaningful if the components inside it are the specified ones.

== Conformance evidence

// Source: docs/SECURITY.md (Evidence summary); crates/vyra-sig/tests/data/PROVENANCE.md;
// crates/vyra-hqc/tests/data/PROVENANCE.md; docs/ATTEMPTS.md (U10, U12, U12-R1, U3-R5).
#figure(
  caption: [Component conformance evidence (gate F4). All official vectors run through VYRA's
    adapters except where noted.],
  tsmall(table(
    columns: (auto, 1fr),
    align: left,
    table.hline(stroke: 0.6pt),
    table.header([*Component*], [*Evidence*]),
    table.hline(stroke: 0.4pt),
    [ML-KEM], [IETF LAMPS example key; differential interoperation with the independent `fips203` 0.5.0 crate],
    [HQC v5.1], [all 100 official KAT counts per parameter set (pk, sk, ct, ss), through the crate and the adapter; 200 official Reed--Solomon vectors per set; 2000 random round trips per set; a negative control shows the KAT check can fail],
    [ML-DSA], [NIST ACVP keyGen (75), sigGen (90; signing driven through upstream with expanded keys, signatures verified by the adapter), sigVer (45); differential tests against `fips204` 0.5.0],
    [SLH-DSA], [NIST ACVP keyGen (30), sigGen (42, byte-exact through the adapter), sigVer (42); differential tests against `slh-dsa`],
    [Ed25519(ph)], [RFC 8032 §7.1 vectors 1--3; the §7.3 Ed25519ph vector through the composite half path; an independent test-side reference on 24 context cases],
    table.hline(stroke: 0.6pt),
  )),
) <tab-conf>

*Limits.* KATs exercise honest key generation, encapsulation and decapsulation. The official HQC
v5.1 KAT files contain no invalid ciphertexts (their generator only checks that decapsulation
returns the same key), so the implicit-rejection path of an FO-transformed KEM, the only part that
malformed inputs reach, has no external known answers; VYRA's port is checked there only against
itself. No independent second implementation of HQC v5.1 exists to test against. Running ACVP
vectors is not certification.

== The HQC port

*Why it exists.* VYRA first used the pure-Rust crate `hqc-kem` 0.1.0-rc.0, the only one that passed
our conformance tests. Its documentation cites a reference commit (`161cd4f`) that is not in the
history of the official repository; its KAT files match, by git blob id, an untagged commit
(`cefbc8c`) between the v5.0.0 and v5.1.0 tags (`crates/vyra-hqc/NOTICE.md`). While writing the
security analysis we found that v5.1 raised the secret weights of all three parameter sets
#cite-n("HQC-SPEC", "CHLT26"), so the crate implemented parameters the designers had superseded.
Key, ciphertext and shared-secret lengths did not change, so nothing on the wire revealed the
mismatch, and implicit rejection would have hidden it at run time (RULES 17, 20). No pure-Rust v5.1
implementation existed on 2026-11-18, so `vyra-hqc` is a fork of `hqc-kem` modified to v5.1
(decision D-14).

*What changed.* The v5.1 changes from the reference implementation tag `v5.1.0`
#cite-n("HQC-REF"): raised weights $omega$ (67/101/132) and $omega_r = omega_e$ (76/114/150); seed
expansion without a domain byte; the $bb(F)_(2^8)$ polynomial 0x11B with primitive element 3 and new
Reed--Solomon generator polynomials; new Reed--Muller generator rows; a rewritten Reed--Solomon
decoder; and the 32-byte seed as the decapsulation key. The port is accepted only because it
reproduces every official KAT case (RULES 24), including the KAT generator's AES-256 CTR DRBG with
its exact request boundaries (RULES 22).

*No `unsafe`, no secret-indexed table.* Upstream multiplies binary-polynomial words with PCLMULQDQ
through `unsafe` on x86-64, and otherwise with a window kernel that indexes a table by operand bits,
a secret-dependent memory access when the operand is secret. The port removes both. Its default
kernel builds the 64×64-bit carry-less product from 25 ordinary integer multiplications of operands
masked into five interleaved bit classes (the "holes" technique credited to BearSSL's
`ghash_ctmul64.c`): each class holds at most 13 bits, so column sums of at most 13 fit below the next
bit of the same class and carries never corrupt it; with four classes a column could reach 16 and
overflow. The kernel is constant time _only if the CPU's 64×64→128-bit multiplier is_, which the
crate states for current x86-64 and AArch64 cores and which is not guaranteed elsewhere; it is
therefore compiled only for those two architectures, every other target gets a multiplier-free
shift-and-XOR kernel, and a cargo feature forces the latter. Both kernels are tested against a naive
bit-by-bit product. The integer kernel measured 3.4--4.8 times faster than the earlier bit-serial
port; we did not compare against upstream's PCLMULQDQ path.

*Timing smoke test, not a constant-time proof.* Dudect-style Welch $t$-tests (valid versus
corrupted ciphertexts in decapsulation; two seeds in key generation; all three sets) were run once
on one machine with 1500--3000 samples per class; every $|t|$ was below 1.6. This rules out only
gross leaks in that run. Seven forked arithmetic modules allow Clippy's `indexing_slicing` (152 sites,
inherited fixed-bound indexing), so the no-panic gate S8 is not evidence for them.
