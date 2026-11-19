# Design decisions and deviations from the research report

The research report (`docs/research/vyra-deep-research-report.md`) is the design
starting point. Reading it against the literature turned up several statements
that are wrong or cannot be implemented responsibly. Each is listed here with
the evidence and what VYRA does instead. Nothing below was changed silently.

## D-01 The report's combiner `K = KDF(k1 || k2)` is not robust — REPLACED

**Report:** `K ← KDF(concat(k1, k2))`, claimed IND-CCA "if at least one sub-KEM is IND-CCA".

**Problem:** That claim is false for this combiner. Giacon, Heuer and Poettering
("KEM Combiners", PKC 2018) show that a combiner hashing only the component keys
is not CCA-robust: if one component is broken so that an attacker can maul its
ciphertext `c1 → c1'` without changing `k1`, then `(c1', c2)` is a *different*
hybrid ciphertext that decapsulates to the *same* `K`, and the IND-CCA
decapsulation oracle hands the challenge key to the attacker. The whole point of
a hybrid is to survive one component being broken, so this is the case that matters.

**VYRA:** the combiner binds both ciphertexts, both public keys and the suite:

    K = SHA3-256( frame("VYRA-KEM-v1") ‖ frame(suite) ‖ frame(ss1) ‖ frame(ss2)
                  ‖ frame(ct1) ‖ frame(ct2) ‖ frame(pk1) ‖ frame(pk2) )

where `frame(x) = u64_be(len(x)) ‖ x`. Hashing the ciphertexts is the GHP18
construction (secure in the ROM if either component is IND-CCA). Hashing the
public keys adds binding in the multi-key setting. This is VYRA-ORIGINAL only in
its concrete encoding; the technique is established.

## D-02 "Decaps returns ⊥ on invalid" does not match the components — CORRECTED

ML-KEM (FIPS 203) and HQC both use *implicit* rejection: an invalid ciphertext
yields a pseudorandom key, never an error. VYRA therefore also rejects
implicitly. `decapsulate` returns `Err` only for *malformed* input (wrong
length, wrong header), which is public information.

## D-03 Forward secrecy claim is wrong for static keys — CORRECTED

The report says compromise of the long-term `(sk1, sk2)` "does not reveal past
session keys". With a static recipient key it does: anyone holding `sk` can
decapsulate every recorded ciphertext. Forward secrecy needs a fresh key pair per
session that is erased afterwards. VYRA documents this; the handshake example
uses ephemeral key pairs. The KEM alone provides no forward secrecy.

## D-04 POLKA "dummy ciphertext" and "rigidity" countermeasures — NOT IMPLEMENTED

POLKA (Hoffmann et al., PKC 2023) is a distinct encryption scheme designed from
scratch for leakage resilience. Its techniques are not a wrapper that can be
applied to ML-KEM or HQC. Removing the FO re-encryption check from ML-KEM
("rigidity … with parameter tweaks") would produce a non-FIPS-203 primitive with
no security analysis. Implementing that would be inventing an unanalysed
primitive, which the build rules forbid. VYRA uses the standardised components
unmodified and makes **no** leakage-resilience claim.

## D-05 Masking, fault countermeasures, DPA testing — NOT IMPLEMENTED

Masking and fault redundancy live inside the component primitives. VYRA does not
reimplement them, has no power/EM measurement setup, and claims no protection
against physical attackers. What VYRA does: zeroise secrets, compare in constant
time, and avoid secret-dependent control flow in its own glue code. Timing
behaviour of the upstream crates is inherited and unverified here.

## D-06 Security level statements — CORRECTED

"Kyber-768 + HQC-192 (~2^192 quantum)" is not a meaningful statement. NIST
categories are defined relative to key search on AES (1/3/5) under classical and
quantum cost models. VYRA quotes the NIST category claimed by each component and
nothing stronger. The hybrid's category is the *minimum* of its components'.

## D-07 Table errors in the report — CORRECTED IN SPEC

- Falcon-512 is NIST category 1, not 3.
- ML-DSA rests on Module-LWE **and** Module-SIS (SelfTargetMSIS), not MLWE alone.
- "Classic McEliece (1–2 KB keys)" is wrong; public keys are 261 KB – 1.3 MB.
- "224472 cycles" for Kyber-768 is uncited; VYRA reports only its own measurements.
- HQC sizes are taken from the implemented parameter sets, not from the report.

## D-08 Signatures — SCOPED

Implemented: composite ML-DSA + Ed25519 (both must verify), with a domain
separated, context-bound message encoding. Not implemented: the ML-DSA +
SLH-DSA "extreme cases" option (marked optional in the report), threshold
signing and multi-party decryption (the report gives no construction).
Ed25519 offers ~128-bit classical security and none against a quantum
attacker; pairing it with ML-DSA-87 is a category mismatch that is documented.

## D-09 "Leakage-resilient commitments" — NOT IMPLEMENTED

The report marks this "tentative" and gives no construction. Nothing to implement.

## D-10 Language

The report's roadmap says C/Python. The project owner chose Rust. All VYRA code
is safe Rust (`#![forbid(unsafe_code)]`); components come from existing crates.

## D-11 HQC is pinned to a pre-standard snapshot — OPEN, NEEDS OWNER DECISION

HQC has no final standard yet (FIPS 207 is pending). The only pure-Rust
implementation that passed conformance testing, `hqc-kem =0.1.0-rc.0`,
reproduces the official reference KATs at `gitlab.com/pqc-hqc/hqc` commit
`161cd4f` (2026-02-13). That commit lies between the tagged v5.0.0 (2025-08-22)
and v5.1.0 (2026-10-26) releases and is interoperable with neither. Sizes equal
the v5.0.0 table. Consequences:

- VYRA-KEM v1 ciphertexts and keys are **not** interoperable with any released
  HQC version and will not be with FIPS 207.
- When a conformant FIPS 207 crate exists, the HQC adapter must be swapped and
  the VYRA wire version bumped (the `Kem` trait makes this a local change).
- A test (`hqc_version_pin`) fails if the dependency version moves.

## D-12 Secret keys are stored as seeds where the standard allows

ML-KEM secret keys are the 64-byte FIPS 203 seed `d‖z`; ML-DSA secret keys are
the 32-byte FIPS 204 seed `ξ`. Every seed is a valid key, so there is no
malformed-expanded-key path. Cost: key expansion on every private operation.

### D-11 addendum — the pinned HQC parameters have been superseded by the designers

Found while writing the security analysis (verified against the HQC v5.1
specification changelog on pqc-hqc.org): v5.1 raises the secret weight ω by 1
for all three parameter sets and ω_r by 1 for HQC-1 and HQC-5, citing
cryptanalytic improvements (Carrier, Hatey, Luzzi, Tillich, ePrint 2026/1498).
v5.1 also changes the GF(2^8) polynomial and makes the seed-only secret key the
default. The snapshot VYRA uses (`161cd4f`) has the **older, lower weights**.

Consequence: the NIST category 1/3/5 labels on VYRA's HQC component are the
designers' *superseded* claims. This matters most in exactly the scenario the
hybrid exists for (ML-KEM broken, HQC the only remaining line). No pure-Rust
implementation of v5.1 was found at build time, so this cannot be fixed inside
this project today. It is the single most important reason VYRA-KEM v1 must be
treated as a research artefact. Dates of the v5.1 release quoted above
(2026-10-26) are the repository tag date as reported by the build agent; the
specification PDFs are dated 2026-10-12 and 2026-11-09.

## D-13 HQC secret key stored as its seed

The HQC expanded secret key embeds a copy of the public key that decapsulation
uses but never checks against the secret part. Following RULES 7, VYRA stores
only the HQC key-generation seed and re-derives the key pair on use, as it does
for ML-KEM and ML-DSA. (Implemented in repair U2-R2.)

## D-14 HQC upgraded to the v5.1 specification via an in-tree port — RESOLVES D-11

D-11 and its addendum recorded that VYRA's HQC half was pinned to a pre-standard
snapshot with superseded parameters. That is no longer the case.

- **What:** `crates/vyra-hqc` is a pure-Rust implementation of HQC v5.1
  (specification dated 2026-11-09; reference implementation tag `v5.1.0`, commit
  `06567ccb`). It is a fork of `hqc-kem 0.1.0-rc.0` (MIT OR Apache-2.0, RustCrypto
  developers; attribution in `crates/vyra-hqc/NOTICE.md`) with the v5.1 changes
  applied: raised weights ω/ω_r/ω_e, new XOF seed-expansion framing, GF(2^8)
  polynomial 0x11B, new Reed–Muller generator rows, rewritten Reed–Solomon
  decoder, and the compressed (seed) decapsulation key.
- **Why a fork:** no pure-Rust crate implemented v5.1 on 2026-11-18 (hqc-kem,
  oqs-native-hqc, backbone-hqc and lib-q-hqc were all checked).
- **Evidence:** all 100 official v5.1 KAT counts for each of HQC-1/3/5 match
  (pk, sk, ct, ss) through the crate and through VYRA's adapter; 200 official
  Reed–Solomon vectors per set; a negative control shows the KAT check can fail.
  There is **no independent second implementation of v5.1** to test against, so
  the official KATs are the only conformance evidence.
- **What this does not change:** HQC is still not a published FIPS standard
  (FIPS 207 is pending) and may change again; the port is new code reviewed only
  inside this project; its constant-time behaviour is argued by structure and a
  coarse timing smoke test, not measured rigorously. The forked arithmetic
  modules allow `clippy::indexing_slicing` (fixed-bound array indexing), so gate
  S8 is not evidence for those seven modules.
- **RULES 2** ("never wrap, tweak, or strip checks from a standardised
  primitive") is respected in the sense that matters: the port implements the
  designers' specification exactly and is accepted only because it reproduces
  their test vectors. It is, however, VYRA-maintained cryptographic code, and
  should be replaced by an audited upstream crate when one exists.
- **Wire version:** the version byte stays 1. No VYRA artefact was ever released
  with the snapshot-based HQC, so "v1" is defined as the format at first
  publication of the repository. Development snapshots before commit "HQC v5.1"
  used the same byte with different HQC parameters and are not VYRA v1; their
  ciphertexts would decapsulate to unrelated keys (implicit rejection).
- D-13 (seed-form HQC secret key) now coincides with the v5.1 default: VYRA's
  stored 32-byte seed is exactly the specification's compressed decapsulation key.

### D-11 / D-14 provenance correction

D-11 names reference commit `161cd4f` (taken from a third-party crate's own
description). While porting, that hash could not be found in the official
repository history; the KAT files shipped by `hqc-kem 0.1.0-rc.0` are
byte-identical (by git blob id) to those at commit `cefbc8c` ("Update sampling",
2026-02-10). `crates/vyra-hqc/NOTICE.md` records this. The earlier text is kept
as written because it is part of the record.

## D-15 What the name means, and what it does not

VYRA stands for **Verified Yielding Resistance Architecture**. Each word is a
claim, so each is defined here by the evidence that backs it.

- **Yielding Resistance:** the security goals are meant to survive one
  component family *yielding* (being broken). For key establishment the two
  families are module lattices (ML-KEM) and codes (HQC). For signatures the
  dual post-quantum suites pair module lattices (ML-DSA) with hash functions
  (SLH-DSA); the transition suites pair ML-DSA with Ed25519 and give no second
  line against a quantum attacker. Evidence: a cited theorem for the combiner
  technique, proof sketches with listed gaps, and failure-injection experiments
  (D-16). No security proof exists for VYRA's concrete instantiation.
- **Verified:** the claims VYRA makes about *behaviour* are tied to reproducible
  machine checks — official known-answer vectors for the components, failure-injection
  games for the compositions, exhaustive enumeration and bounded model checking
  for VYRA's own encodings (D-18), and the gate list in `docs/CHECKS.md`.
  Statements that rest on inspection or on the literature instead (constant-time
  structure of the glue code, parameter categories, the proof sketches) are
  labelled as such in `docs/SECURITY.md` and are not covered by the word. It
  does **not** mean formal verification of the cryptography, verified
  constant-time behaviour, or review by anyone outside this project.
- **Architecture:** components sit behind small traits and can be replaced; the
  same composition code runs the named suites and custom assemblies.

## D-16 Yielding resistance is tested by failure injection

`crates/vyra-yield` builds deliberately broken components (leaky, malleable,
key-substitutable, constant, forgeable, context-ignoring, …), plugs them into
the real composition code, and runs executable adversaries in explicit games
(IND-CCA2 and binding games for the KEM; EUF/SUF-CMA, separation, exclusive
ownership, mix-and-match and cross-suite/context games for signatures) against
VYRA's design and against comparison designs (the original report's
`KDF(k1‖k2)`, XOR, ciphertext-only binding, plain concatenation, "either half").
`results/yield-matrix.*` is the deterministic output; gates Y1/Y2 keep it
current. This is falsification evidence against idealised failure models, not a
proof, and says nothing about real cryptanalysis, quantum adversaries or side
channels.

## D-17 Dual post-quantum signature suites; the Ed25519 half is context-bound

- Added `VYRA-SIG-PQ1/PQ3/PQ5` = ML-DSA-44/65/87 + SLH-DSA-SHAKE-128s/192s/256s
  (FIPS 205, via the `fips205` crate; all embedded official ACVP vectors pass
  through VYRA's adapter). Signatures are 10–34 KB and signing takes seconds.
  This reverses the "not implemented" part of D-08.
- Failure injection showed that in the transition suites, once ML-DSA is
  modelled as forgeable, the composite was forgeable by anyone with a standalone
  Ed25519 signing oracle on the same key, because the Ed25519 half was a valid
  PureEd25519 signature on the bound message. The Ed25519 half is now RFC 8032
  Ed25519ph under the composite context, so no half in any named suite is a
  valid default-mode standalone signature. Cost: that half now signs
  SHA-512(M'), so a SHA-512 collision on M' forges *that half* (the ML-DSA half
  signs M' unhashed).
- Known coincidence: VYRA-SIG-2 and VYRA-SIG-PQ1 public keys are both 1344 bytes
  raw, so a relabelled public key parses. It fails closed: the suite id is in the
  signed message, the contexts and the public-key digest, and signature lengths
  differ, so nothing verifies under a relabelled key.

## D-18 Machine-checked properties of VYRA's own encodings

`crates/vyra-proofs` holds (a) exhaustive enumeration tests over exactly stated
finite domains and (b) Kani bounded-model-checking harnesses, run in a pinned
Docker image by `tools/kani/run.*`, with a mutation check for each. They cover
the wire parser, the bounds-checked reader, transcript framing, constant-time
equality's functional behaviour, the entropy adapter's failure latching, and the
signature message layout. The complete suite ran on 2026-11-19: 413 harnesses
successful, 12 of 12 injected mutants killed by a property failure. Bounds, results and what is not covered are in
`tools/kani/RESULTS.md` and `results/kani-report.txt`. SHA-3, the component
algorithms, timing, and anything beyond the stated bounds are out of scope.

### Reviewer notes on the yield experiment (kept with the decision record)

The documentation pass reviewed the experiment's design and found limits that
are now stated wherever its results are quoted: most cells carry no
pre-registered expectation and are observations; the negative control cannot
detect binding weaknesses of the real components because no adversary targets
them; with N = 200 only large-advantage attacks are visible; adversaries are
game-specific, so some "no attack found" cells for doubly-broken designs reflect
adversary selection; and the standalone-oracle game excludes, by definition, an
oracle that signs under the composite's own context.
