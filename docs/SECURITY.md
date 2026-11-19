# VYRA security analysis

This is the security analysis of VYRA wire version 1 (`docs/SPEC.md`) against
the threat model in `docs/THREAT_MODEL.md`. (The vulnerability-reporting policy
is `SECURITY.md` at the repository root.)

**Summary.** VYRA combines components that are designed to resist known
classical and quantum attacks (ML-KEM, HQC, ML-DSA, SLH-DSA) with a classical
component (Ed25519) and symmetric primitives, using established composition
techniques in VYRA-ORIGINAL encodings. Its main results of its own are a
failure-injection experiment (§Failure-injection evidence), which found one
real weakness in an earlier signature design that has since been fixed, and
machine checks of its own encodings (§Machine-checked properties).
VYRA itself has had **no independent analysis**: no external cryptanalysis, no audit, no side-channel evaluation, and no
written security proof for its concrete instantiation. This document states
what is established in the literature (with citations, each marked as verified
online or from memory), what is argued here only as a sketch, and what is
unsupported.

**Most important caveat.** VYRA's HQC component is VYRA's **own port**
(`crates/vyra-hqc`) of a scheme that is **not yet standardised** (HQC
specification v5.1; FIPS 207 is unpublished). The port is a fork of the
`hqc-kem` release candidate, modified by the VYRA authors. Its only
conformance evidence is the designers' official known-answer vectors: there is
no independent second v5.1 implementation to cross-check against, and the
port has had no external review and no rigorous constant-time evaluation. The
hybrid exists to survive a break of ML-KEM; in that scenario everything rests
on this port being both a correct and a side-channel-safe implementation of
HQC v5.1. (The earlier caveat, that VYRA pinned superseded pre-v5.1 HQC
parameters, is resolved by DECISIONS.md D-14.)

Evidence labels used below: **[lit]** result established in the cited
literature for the generic technique; **[sketch]** argument written in this
document, not peer reviewed; **[test]** checked by a named test; **[fi]**
failure-injection experiment (`results/yield-matrix.md`); **[enum]**
exhaustive enumeration over a stated finite domain; **[bmc]** bounded model
checking (Kani) up to a stated bound; **[inspection]** checked by reading
code; **[none]** no evidence.

## What the name means

VYRA stands for **Verified Yielding Resistance Architecture** (D-15). Each
word is a claim, so each is defined here by the evidence behind it.

| Word | Meaning in VYRA | Evidence class | Explicitly NOT claimed |
|------|-----------------|----------------|------------------------|
| **Yielding Resistance** | The security goals are designed to survive one component family *yielding* (being broken): ML-KEM or HQC for key establishment; ML-DSA or SLH-DSA in the dual post-quantum signature suites. The transition signature suites (ML-DSA + Ed25519) give no second line against a quantum adversary. | [lit] GHP18 for the combiner technique; [sketch] the proof sketches below, with listed gaps; [fi] the failure-injection experiment (§Failure-injection evidence) | no security proof for VYRA's concrete instantiation; no statement about real cryptanalytic breaks, which may not look like the idealised failure models; no QROM result |
| **Verified** | The claims VYRA makes about *behaviour* are tied to reproducible machine checks: official known-answer vectors for the components, failure-injection games for the compositions, exhaustive enumeration and bounded model checking for VYRA's own encodings (§Machine-checked properties), and the gate list in `docs/CHECKS.md` (D-15). Statements that rest on inspection or on the literature instead (constant-time structure of the glue code, parameter categories, the proof sketches) are labelled [inspection], [lit] or [sketch] here and are not covered by the word. | [test], [fi], [enum], [bmc] | not formal verification of the cryptography; not verified constant-time behaviour; not review or validation by anyone outside this project; not a certification |
| **Architecture** | Components sit behind small traits (`Kem`, `ComponentKem`, `SignatureScheme`, `CompositeComponent`) and can be replaced; the same composition code runs the named suites and custom assemblies (`docs/SPEC.md` §7.8). | [test] byte-equality of custom assemblies with the named suites; [inspection] | no claim that an arbitrary custom assembly is secure; it is only as good as its components |

## Assumptions

### Hardness and idealisation assumptions per primitive

| Primitive | Assumption(s) | Model of the cited proof | Source |
|-----------|---------------|--------------------------|--------|
| ML-KEM (FIPS 203) | Module-LWE (IND-CPA of the inner PKE); IND-CCA2 of the KEM via a Fujisaki–Okamoto variant with implicit rejection | ROM and QROM proofs exist for the FO variants used; VYRA has not checked which proof covers FIPS 203 exactly | FIPS 203 [from memory — verify proof references] |
| HQC (v5.1) | decisional quasi-cyclic syndrome decoding problems **with parity**: 2-DQCSD-P and 3-DQCSD-PT, as named in the HQC v5.1 specification; IND-CPA of HQC-PKE reduces to them (Theorem 6.3), IND-CCA2 of HQC-KEM via the salted FO transform with implicit rejection | ROM (HQC v5.1 spec, Theorem 6.4, "in the random-oracle model"). No QROM statement found in the v5.1 spec | HQC spec v5.1 [verified online]. This is the version VYRA implements (D-14) |
| ML-DSA (FIPS 204) | Module-LWE (key indistinguishability) **and** Module-SIS in the SelfTargetMSIS form (D-07) | Fiat–Shamir with aborts; ROM and QROM analyses exist for Dilithium | FIPS 204; Kiltz–Lyubashevsky–Schaffner 2018 [from memory — verify] |
| SLH-DSA (FIPS 205) | properties of the underlying hash functions only (SHAKE256 here); the SPHINCS+ analyses use PRF, PRF_msg, and target-collision/subset-resilience properties of tweakable hash functions | ROM / standard-model analyses for SPHINCS+ exist; VYRA has not checked which covers FIPS 205 exactly | FIPS 205 [assumption names from memory — verify] |
| Ed25519ph (RFC 8032, composite half) | as Ed25519, plus **collision resistance of SHA-512** on the signed representatives (a SHA-512 collision forges this half; D-17) | as Ed25519 | RFC 8032; D-17 |
| Ed25519 (RFC 8032) | hardness of discrete logarithms in the prime-order subgroup of edwards25519 (ECDLP-type) plus hash properties of SHA-512 | ROM | Brendel, Cremers, Jackson, Zhao 2021 [from memory — verify]. **Broken by Shor's algorithm** on a large quantum computer |
| SHA3-256, SHAKE256 (FIPS 202) | used in VYRA as: random oracle (combiner, KDF), collision-resistant hash (public-key digest, binding), PRF/XOF (KDF) | idealised where noted | FIPS 202 |
| ChaCha20-Poly1305 (RFC 8439) | IND-CPA of ChaCha20 as a PRF-based stream cipher and INT-CTXT from Poly1305 one-time MAC; **each (key, nonce) pair used once** | standard model, assuming ChaCha20 is a PRF | RFC 8439; Procter 2014 [from memory — verify] |

### Which hash property is needed where

| Use | Code | Property needed | Notes |
|-----|------|-----------------|-------|
| KEM combiner `K = SHA3-256(framed …)` | `vyra-kem/src/combiner.rs` | random oracle (or split-key PRF in the sense of GHP18) for IND-CCA2 robustness; collision resistance for binding | see §"The combiner argument" |
| Ed25519ph prehash `SHA-512(M')` | `vyra-sig/src/ed25519.rs` | collision resistance of SHA-512 | forges the Ed25519 half only; the other half signs `M'` unhashed |
| Signature public-key digest | `vyra-sig/src/message.rs` | collision resistance (and second-preimage resistance) of SHA3-256 | binds the whole composite public key into `M'`; not needed for single-key EUF-CMA (see sketch) |
| Sealed-box KDF `SHAKE256(0x01 ‖ …)[0..44]` | `vyra-seal/src/kdf.rs` | PRF / random oracle keyed by the 32-byte `K` | `K` is the only secret input |
| Secret-key check values (`VYRA-KEM-SK-v1`, `VYRA-SIG-SK-v1`) | `vyra-kem/src/keys.rs`, `vyra-sig/src/keys.rs` | none for security; a 16-byte truncated hash used as an error-detecting code (relabelling, corruption) | not a MAC; it is a public function of data stored beside it |
| `DeterministicEntropy` | `vyra-core/src/entropy.rs` | none (test only) | not a security component |

### Domain separation of hash inputs

VYRA's own SHA3-256 inputs all start with `frame(label)` for distinct labels
(`"VYRA-KEM-v1"`, `"VYRA-SIG-PK-v1"`, `"VYRA-KEM-SK-v1"`, `"VYRA-SIG-SK-v1"`),
and framing is injective, so VYRA's uses are separated from each other. The
components also call SHA3-256 internally (ML-KEM `H(ek)`; HQC `H(ek ‖ 0x01)`
and `J(H ‖ sigma ‖ c_kem ‖ 0x03)`, per `crates/vyra-hqc/src/shake.rs`; v5.1
did not change these two functions, only the SHAKE256 seed expansion). Those
inputs are not syntactically prefixed, so separation from VYRA's inputs rests
only on **input length**. All of these lengths are fixed per suite:

| SHA3-256 call site | Input length in bytes (suite 1 / 3 / 5, or per parameter set) |
|--------------------|-------------------------------------------------------------|
| VYRA combiner `19 + 9 + 2·40 + (8 + ct1) + (8 + ct2) + (8 + pk1) + (8 + pk2)` | 8382 / 15904 / 24934 |
| VYRA pk digest `22 + 9 + (8 + pk_first) + (8 + pk_second)` | 1391 / 2031 / 2671 (VYRA-SIG-2/3/5); 1391 / 2047 / 2703 (VYRA-SIG-PQ1/PQ3/PQ5) |
| VYRA KEM secret-key check `22 + 9 + (8 + 96)` | 135 (every suite) |
| VYRA SIG secret-key check `22 + 9 + (8 + sk)` | 103 (transition suites); 119 / 143 / 167 (PQ1/PQ3/PQ5) |
| ML-KEM `H(ek)` | 800 / 1184 / 1568 |
| HQC `H(ek ‖ 0x01)` | 2242 / 4515 / 7238 |
| HQC `J(H ‖ sigma ‖ c_kem ‖ 0x03)`, `32 + k + ct + 1` | 4482 / 9035 / 14486 |

No VYRA row shares a length with a component row (VYRA rows may share lengths with each other, e.g. the VYRA-SIG-2 and VYRA-SIG-PQ1 digests, but those inputs differ in their framed label or suite byte). SLH-DSA (SHAKE256) and Ed25519ph (SHA-512) add no SHA3-256 call sites. This arithmetic is ours (from the sizes in
`docs/SPEC.md` and `vyra-hqc/src/shake.rs`), recomputed with a short script
after the secret-key format change and re-checked after the move to HQC v5.1
(sizes unchanged, H and J framing unchanged), but not checked by any test, and is
only a heuristic justification for treating the combiner's SHA3-256 as an
oracle independent of the components' (see Open questions).

For **SHAKE256** the length argument does not work: ML-DSA hashes the
variable-length, caller-influenced message representative with SHAKE256, so an
input of any length can occur inside ML-DSA. The sealed-box KDF input
(`0x01 ‖ frame("VYRA-SEAL-v1") ‖ …`, containing the secret `K`) is separated from
component uses only heuristically; no argument beyond "the KDF input contains a
fresh secret 32-byte value and a fixed VYRA prefix" is offered. (HQC v5.1's
seed expansion is `SHAKE256(seed ‖ k/8)` or `SHAKE256(seed)` with no prefix,
32 or 33 bytes; it is likewise only heuristically separated.)

### ROM versus QROM, honestly

- The cited combiner result (GHP18) is in the ROM for the hash-based
  instantiation. Don, Fehr and Huang (TCC 2022) proved GHP18's hash-based
  split-key PRF secure in the QROM [verified online]. Neither paper covers
  VYRA's exact encoding (extra inputs: label, suite id, public keys); VYRA has
  no QROM proof.
- The HQC IND-CCA2 claim in the v5.1 specification is in the ROM.
- No proof in any model exists for the composite signature or the sealed box
  in VYRA's exact encoding. The sketches below are classical ROM / standard
  model sketches.

### Trust assumptions

As in `docs/THREAT_MODEL.md` §3: the OS CSPRNG, the platform and compiler, and
the upstream crates. The `ml-kem` 0.3.4 and `ml-dsa` 0.1.2 READMEs each carry
a security warning that the implementation "has never been independently
audited". HQC is implemented by the in-tree crate `vyra-hqc`, VYRA-maintained
code forked from `hqc-kem` 0.1.0-rc.0 (not a runtime dependency any more); its
correctness is trusted on the basis of the official v5.1 KATs only. The
`chacha20poly1305` README reports one NCC Group audit (VYRA did not check which
version it covered). On 2026-11-18, after the HQC change, `cargo audit`
reported no known advisories (122 crates checked against 1533 advisories): a
point-in-time observation about
*known* advisories, not evidence that the dependencies are free of flaws; the
latest recorded status is in `results/verification-report.md`.

## Attack models

### Adversaries considered

Classical and quantum (offline quantum computation, classical interaction);
passive; active IND-CCA2 (decapsulation and sealed-box opening oracles);
CMA (signing oracle with chosen message and context); harvest-now-decrypt-later;
multi-user and multi-target; local timing on VYRA's own code. Physical side
channels, fault injection and compromised endpoints are out of scope
(`docs/THREAT_MODEL.md` §4).

### Best known attack families (as claimed by the component specifications)

VYRA ran **no** lattice estimator, ISD estimator or other cost model. It
quotes the categories claimed by the specifications and makes no bit-security
estimate of its own.

| Target | Attack families | Status in VYRA |
|--------|-----------------|----------------|
| ML-KEM / ML-DSA (MLWE, MSIS) | primal and dual lattice attacks via BKZ with sieving (core-SVP methodology in the Kyber/Dilithium submissions); hybrid and algebraic attacks; quantum: polynomial-factor speedups to sieving, no known exponential speedup | categories 1/3/5 (ML-KEM) and 2/3/5 (ML-DSA) quoted from FIPS 203/204; VYRA re-derived no estimate |
| HQC (QCSD with parity) | information-set decoding (Prange and its improvements), with the DOOM gain of `O(√n)` from quasi-cyclicity; structural attacks on the cyclic polynomial; the v5.1 spec halves classical bit security for quantum (Grover-type speedup of ISD, citing Bernstein "Grover vs. McEliece") | categories 1/3/5 quoted from the v5.1 specification. In v5.1 the HQC team increased the weights (ω by 1 for all sets) to compensate "minor technical cryptanalysis improvements" by Carrier, Hatey, Luzzi, Tillich (ePrint 2026/1498) [verified online, HQC spec v5.1 changelog]; VYRA implements the v5.1 weights (D-14) |
| Decryption-failure attacks (ML-KEM, HQC) | an active adversary searching for failing ciphertexts to learn the secret key | rely on the specs' DFR bounds. HQC v5.1 Table 8 claims DFR `< 2^-127 / < 2^-192 / < 2^-256` for HQC-1/3/5 [verified online]; these are the parameters VYRA implements. ML-KEM: FIPS 203 states decapsulation failure probabilities per parameter set; VYRA did not re-read the values [to be verified] |
| Ed25519 | Pollard rho (generic discrete-log attack; the commonly cited level is roughly 128-bit classical security); **Shor's algorithm** breaks it in polynomial time on a large quantum computer | classical-only component |
| SHA3-256 / SHAKE256 / ChaCha20 / Poly1305 | generic attacks: Grover on 256-bit keys and preimages (≈ 2^128 quantum queries); collisions on 256-bit outputs (≈ 2^128 classically; quantum collision algorithms do not improve on this in realistic cost models [from memory — verify]) | 256-bit output key `K`, 256-bit AEAD key |
| Multi-target | key search over many sealed boxes or many KEM keys; batch ISD/lattice attacks over many public keys | no multi-user analysis; each sealed box uses an independent 256-bit key, which leaves margin for generic multi-target key search, but the components' multi-user security is whatever their own analyses give |
| Combiner-specific | ciphertext mauling of a broken component (the attack on `KDF(k1 ‖ k2)`, below); mix-and-match of public keys; cross-suite reuse | combiner hashes ciphertexts, public keys and suite id |
| SLH-DSA | generic attacks on the hash function (SHAKE256): preimage, second-preimage and multi-target attacks, Grover-type quantum speedups; no algebraic structure | categories 1/3/5 for SHAKE-128s/192s/256s quoted from FIPS 205; VYRA re-derived no estimate |
| Signature-specific | stripping a half, standalone signing oracles on component keys, cross-key splicing, cross-suite relabelling, malleability of one half, a SHA-512 collision against the Ed25519ph half | see the composite argument and §Failure-injection evidence |

## Parameter analysis

All categories below are **claims made by the component designers** (NIST for
FIPS 203/204/205; the HQC team for the HQC v5.1 parameter sets). VYRA ran no lattice
or ISD estimator and has no bit-security figure of its own.

### Per suite

| Suite | Components and their claimed NIST categories | Suite claim (= minimum) | Remarks |
|-------|----------------------------------------------|-------------------------|---------|
| VYRA-KEM-1 | ML-KEM-512 (1), HQC-128 = HQC-1 of v5.1 (1) | 1 | |
| VYRA-KEM-3 | ML-KEM-768 (3), HQC-192 = HQC-3 of v5.1 (3) | 3 | |
| VYRA-KEM-5 | ML-KEM-1024 (5), HQC-256 = HQC-5 of v5.1 (5) | 5 | |
| VYRA-SIG-2 | ML-DSA-44 (2), Ed25519 (classical ≈ 128 bit; none vs. quantum) | label 2 = ML-DSA-44 | ML-DSA-44 is category 2, not 1 (corrected in U1b, see ATTEMPTS) |
| VYRA-SIG-3 | ML-DSA-65 (3), Ed25519 (classical only) | label 3 = ML-DSA-65 | **category mismatch:** the classical fallback stays at ≈ 128 bit |
| VYRA-SIG-5 | ML-DSA-87 (5), Ed25519 (classical only) | label 5 = ML-DSA-87 | **category mismatch**, as above (D-08) |
| VYRA-SIG-PQ1 | ML-DSA-44 (2), SLH-DSA-SHAKE-128s (1) | 1 | minimum of the two |
| VYRA-SIG-PQ3 | ML-DSA-65 (3), SLH-DSA-SHAKE-192s (3) | 3 | |
| VYRA-SIG-PQ5 | ML-DSA-87 (5), SLH-DSA-SHAKE-256s (5) | 5 | |

- The hybrid's category is the minimum of the components' (D-06). Combining two
  category-3 KEMs does **not** make a higher category; the hybrid's purpose is
  robustness if one assumption fails, not added strength.
- For signatures the label is the ML-DSA component's only. Against a quantum
  adversary Ed25519 contributes nothing; against a classical adversary who
  breaks ML-DSA, the composite falls back to ≈ 128-bit Ed25519 in every suite.
- The KEM output `K` is 256 bits; the sealed-box AEAD key is 256 bits and the
  derived nonce 96 bits. Generic quantum key search on 256-bit keys costs
  ≈ 2^128 Grover iterations, consistent with category 5. These are generic
  statements, not VYRA-specific estimates.

### HQC: version 5.1, pre-standard, in-tree port (D-14)

- VYRA implements the **HQC specification version 5.1 (2026/11/09)** and the
  reference implementation at tag `v5.1.0` (commit `06567ccb`), through the
  in-tree crate `vyra-hqc` (D-14, which resolves D-11 and its addendum).
- Parameters, as in the v5.1 specification Table 8 [verified online] and
  `vyra-hqc/src/params.rs`: weights ω = 67 / 101 / 132 and ω_r = ω_e = 76 /
  114 / 150 for HQC-1/3/5; claimed DFR `< 2^-127 / < 2^-192 / < 2^-256`;
  claimed NIST categories 1 / 3 / 5. Relative to v5.0 the designers raised ω by
  1 for all sets and ω_r by 1 for HQC-1 and HQC-5, "to increase the scheme's
  security and compensate the minor technical cryptanalysis improvements" of
  ePrint 2026/1498 (v5.1 changelog). The categories are therefore again the
  designers' **current** claims; their basis is the designers' attack-cost
  analysis (ISD with the DOOM gain, Grover-type speedup for quantum), which VYRA
  has not re-derived.
- HQC is still **not a published standard**: FIPS 207 is pending (NIST
  announced in March 2025 a draft for public comment in about a year and a
  final standard in 2027 [verified online]) and may change parameters or
  encodings again, which would require a wire version bump.
- Interoperability evidenced: KAT-level conformance with the v5.1 reference
  implementation (all 100 official KAT counts per set: public key, secret key,
  ciphertext and shared secret). Not evidenced: conformance to FIPS 207;
  interoperation with any other v5.1 implementation (none independent exists);
  behaviour on inputs outside the KAT distribution beyond VYRA's own property
  and tamper tests.

## The combiner argument

### What GHP18 establishes [lit, verified online]

Giacon, Heuer and Poettering (PKC 2018) define the **parallel combiner**: run
the ingredient KEMs in parallel, output ciphertext `c1 ‖ … ‖ cn` and key
`W(k1, …, kn, c1 ‖ … ‖ cn)` for a *core function* `W`. They show that if `W`
is a **split-key PRF** (a PRF in each one of its key arguments, with the
ciphertext vector as input) and at least one ingredient KEM is IND-CCA secure,
the combined KEM is IND-CCA secure. They give hash-based split-key PRFs proven
in the ROM and one standard-model construction. (Construction details as
summarised by Millerjord, Stebila and Steckel, IACR CiC 2026 [verified
online]; the GHP18 PDF itself could not be fetched, so theorem numbers are not
given here.) Millerjord et al. also point out that GHP18 assumes the combined
KEM's keys are not used with the ingredient KEMs outside the combiner, and give
an extended model in which that reuse is captured.

### Why the report's `K = KDF(k1 ‖ k2)` fails (D-01)

Let component 1 be IND-CCA2 and component 2 be a KEM whose ciphertexts can be
mauled without changing the key: given `c2`, an adversary computes `c2' ≠ c2`
with `Decaps2(sk2, c2') = Decaps2(sk2, c2)`. (Example: a KEM whose
decapsulation ignores one ciphertext bit. Such a KEM is not IND-CCA2, which is
exactly the "one component broken" case a hybrid must survive.)

1. The challenger gives the challenge `(c1*, c2*)` and `K_b`.
2. The adversary submits `(c1*, c2')` to the decapsulation oracle; it is a
   different hybrid ciphertext, so the query is allowed.
3. The oracle returns `KDF(Decaps1(c1*) ‖ Decaps2(c2')) = KDF(k1* ‖ k2*) = K_0`.
4. The adversary compares with `K_b` and wins with probability 1, **whatever
   the strength of component 1**.

With the ciphertexts hashed into the key, the oracle's answer on `(c1*, c2')`
is `H(…, c1*, c2', …)`, an independent random-oracle value, and the attack
disappears.

### VYRA's combiner

```text
K = SHA3-256( frame("VYRA-KEM-v1") ‖ frame([suite]) ‖ frame(ss1) ‖ frame(ss2)
              ‖ frame(ct1) ‖ frame(ct2) ‖ frame(pk1) ‖ frame(pk2) )
```

This is the GHP18 parallel combiner with a hash-based core function, plus
extra public inputs (label, suite id, both public keys). It matches the shape
the CFRG hybrid-KEM draft calls the "UniversalCombiner" (shared secrets, both
ciphertexts, both encapsulation keys, label) [verified online]; X-Wing instead
omits the ML-KEM ciphertext and relies on a property of ML-KEM [verified
online]. VYRA hashes everything, which costs hashing ≈ 8–25 KB per operation
and needs no component-specific property.

### PROOF SKETCH (ROM, single user, honest keys) — not peer reviewed

*Claim.* Model `H(x) = SHA3-256(x)` on combiner inputs as a random oracle with
256-bit output. If component `i ∈ {1, 2}` is IND-CCA2 secure, then VYRA-KEM is
IND-CCA2 secure; for any adversary `A` making `q_H` oracle queries there is an
adversary `B` against component `i`, with about the same running time, such
that, up to small constant factors that this sketch does not track,

```text
Adv^{ind-cca2}_{VYRA-KEM}(A) ≤ c · Adv^{ind-cca2}_{KEM_i}(B) + c' · q_H / 2^256 .
```

*Sketch* (for `i = 1`; `i = 2` is symmetric). Let `x(s1, s2, c1, c2) =
frame("VYRA-KEM-v1") ‖ frame([suite]) ‖ frame(s1) ‖ frame(s2) ‖ frame(c1) ‖
frame(c2) ‖ frame(pk1) ‖ frame(pk2)` for the fixed target public key.

- **Game 0** is the real IND-CCA2 game with the real key `K* = H(x(ss1*,
  ss2*, ct1*, ct2*))`.
- **Game 1** is Game 0 with `ss1*` replaced *everywhere* by an independent
  uniform 32-byte `k̃`: in the challenge key, and in every decapsulation query
  whose first component equals `ct1*`.
- **Hop 0→1 (reduction to component 1).** `B` receives `pk1*`, a challenge
  `(ct1*, k_b)` and a decapsulation oracle for component 1. It generates
  `(pk2, sk2)` itself, gives `A` the key `pk1* ‖ pk2`, encapsulates
  `(ct2*, ss2*)` itself and gives `A` the challenge ciphertext `ct1* ‖ ct2*`
  with key `H(x(k_b, ss2*, ct1*, ct2*))` (or a random key, according to `A`'s
  own challenge bit). For a decapsulation query `ct1 ‖ ct2 ≠ ct1* ‖ ct2*`, `B`
  decapsulates `ct2` itself; if `ct1 ≠ ct1*` it asks its oracle for `ss1`; if
  `ct1 = ct1*` it uses `k_b`. It then evaluates `H` itself. If `k_b` is the
  real key, `B` simulates Game 0 exactly; if `k_b` is random, Game 1 exactly.
  `B` never needs to program `H` or to see `A`'s hash queries.
- **Hop 1→ideal.** In Game 1 the challenge key is `H(x*)` with `x*` containing
  the uniform secret `k̃`. No decapsulation answer is `H(x*)`: every allowed
  query has `(ct1, ct2) ≠ (ct1*, ct2*)`, hence a different input by
  injectivity of framing. `A` learns anything about `H(x*)` only by querying
  `H` on `x*`, which requires guessing `k̃`: probability at most `q_H / 2^256`.

*Gaps of this sketch.*

1. It is a sketch: constants, the exact advantage bookkeeping, and the
   formal game definitions are not written out or checked.
2. **QROM.** Hop 0→1 does not use the oracle model; hop 1→ideal is a one-way-
   to-hiding-type step. Don–Fehr–Huang give a QROM proof for GHP18's hash-based
   split-key PRF; VYRA's encoding has extra inputs and has no QROM proof.
3. **Shared oracle.** SHA3-256 is also used inside ML-KEM and HQC. The sketch
   treats the combiner's SHA3-256 as an independent random oracle, justified
   only by the input-length separation noted under Assumptions. This is a
   heuristic step.
4. **Key reuse.** The sketch assumes component keys are used only inside VYRA.
   The public component types (`MlKem768`, `Hqc192`, …) make standalone use
   possible; the extended model of Millerjord–Stebila–Steckel is not analysed.
5. **Multi-user.** No multi-user or multi-challenge bound; no tightness claim.
6. **Binding.** The sketch says nothing about binding. Informally: by collision
   resistance of SHA3-256, equal `K` from two decapsulations implies equal
   `(suite, ss1, ss2, ct1, ct2, pk1, pk2)` except with collision probability.
   Because `pk1`, `pk2` are taken from the secret key at decapsulation, this
   points toward the LEAK/HON/MAL-BIND-K-CT and -K-PK notions of Cremers, Dax
   and Medinger [verified online] for the hybrid **independently of the
   components' binding properties**; the CFRG draft gives a similar informal
   argument for its UniversalCombiner. No proof is written for VYRA, and the
   K-binds-*shared-secret* direction is not addressed.
7. **HQC implementation.** The `i = 2` case depends on HQC-KEM v5.1 being
   IND-CCA2 (the specification's ROM proof, Theorem 6.4) **and** on VYRA's
   port `vyra-hqc` implementing exactly that scheme. The latter is supported
   by the official KATs only (all 100 counts per set), which exercise honest
   key generation, encapsulation and decapsulation but not the rejection path
   against a second implementation.
8. **Implicit rejection.** The sketch assumes the components' decapsulation
   behaves as in their IND-CCA2 games; with implicit rejection there is no
   error oracle. VYRA returns errors only for public-length and own-key
   conditions (D-02) [test, inspection].

## The composite signature argument

Construction (`docs/SPEC.md` §7): both components sign
`M' = "VYRA-SIG-v1" ‖ [suite] ‖ pk_digest ‖ [len(ctx)] ‖ ctx ‖ M` under the
composite context `"VYRA-SIG-v1" ‖ [suite]` through a context-bearing mode
(ML-DSA and SLH-DSA through their FIPS 204/205 context input; Ed25519 as
Ed25519ph); verification requires public-key validation and both halves.

### Intended property per family (not proven for the exact encoding)

| Family | Suites | Intended property | Assumptions it rests on |
|--------|--------|-------------------|-------------------------|
| Dual post-quantum | VYRA-SIG-PQ1/PQ3/PQ5 | EUF-CMA if **ML-DSA or SLH-DSA** is EUF-CMA, against classical and quantum adversaries | MLWE + SelfTargetMSIS (ML-DSA) **or** the hash-function properties SLH-DSA relies on; SHA3-256 collision resistance for cross-key separation only |
| Transition | VYRA-SIG-2/3/5 | EUF-CMA if ML-DSA is EUF-CMA (classical and quantum adversaries), **or** against classical adversaries if Ed25519ph is EUF-CMA | one post-quantum assumption (ML-DSA) plus one classical assumption (ECDLP-type, broken by Shor) and SHA-512 collision resistance for the Ed25519ph half |

### PROOF SKETCH (EUF-CMA, single key, component keys used only through the composite) — not peer reviewed

*Claim.* If component 1 (ML-DSA under the fixed composite context) or
component 2 (SLH-DSA under the composite context, or Ed25519ph under the
composite context) is EUF-CMA, the composite is EUF-CMA for messages
`(M, ctx)`.

*Sketch for component `i`.* `B` gets a public key and a signing oracle of
component `i` for the composite context. It generates the other component's
key itself, builds `pk`, and answers `A`'s signing queries `(M, ctx)` by
computing `M'`, asking its oracle for half `i` on `M'`, and producing the
other half itself. A forgery on a pair `(M, ctx)` never queried yields an `M'`
never queried (for fixed `pk`, `(ctx, M) → M'` is injective), so half `i` is a
forgery of component `i` on a fresh message. The reduction is tight and needs
no collision resistance of SHA3-256 because `pk` is fixed.

*The Ed25519ph assumption delta (D-17).* Half 2 of the transition suites signs
`SHA-512(M')`. An Ed25519ph forgery on a fresh `M'` therefore also follows
from a SHA-512 collision `SHA-512(M'_1) = SHA-512(M'_2)` with `M'_1` queried:
the stored signature on `M'_1` is a valid Ed25519ph half on `M'_2`. This
forges **that half only**: the ML-DSA half signs `M'` unhashed, so a composite
forgery additionally needs an ML-DSA signature on `M'_2`. In the transition
family, "EUF-CMA against classical adversaries if Ed25519ph is" therefore
includes "and SHA-512 is collision resistant on representatives".

*Gaps.*

1. Sketch only; no QROM argument; no multi-user argument; no proof for the
   exact encoding; not the IETF format (RFC 10073) and inherits none of its
   analysis.
2. **Quantum adversary, transition family.** An adversary who computes Ed25519
   discrete logarithms produces the Ed25519ph half for any `M'`; the
   transition composite then reduces to ML-DSA alone.
3. **SUF-CMA.** Strong unforgeability needs **both** components SUF-CMA: if
   either half can be mauled into a different valid half on the same `M'`, the
   other half can be kept and a new composite signature on an old message
   results. This gap is observed in the failure-injection experiment (one
   Malleable or Forgeable component breaks SUF-CMA) [fi]. Whether the
   implementations are SUF-CMA is the component designers' claim, not
   checked here [from memory — verify].
4. **Key reuse outside the composite.** The sketch assumes component keys sign
   only through the composite. What is now true, and how it is evidenced:
   - In every named suite **neither half is a valid standalone default-mode
     signature** (empty-context ML-DSA / SLH-DSA, PureEd25519) on `M'`
     [test: `separation.rs`, e.g. `ed25519_half_is_not_a_standalone_pure_ed25519_signature`,
     `standalone_pure_ed25519_signature_is_not_a_composite_half`,
     `standalone_component_signatures_over_m_prime_do_not_assemble`,
     `neither_half_is_standalone_pq1`, `neither_half_is_standalone_pq3`, `neither_half_is_standalone_pq5`].
   - In the failure-injection game STRIP-STANDALONE the adversary has
     standalone signing oracles on **both** component keys in four modes:
     default mode (PureEd25519; empty-context ML-DSA / SLH-DSA), the context
     variant with the empty context (Ed25519ph with `""`), the context variant
     with a foreign application context, and the context variant with
     **another VYRA suite's** composite context. Against `Vyra` no attack was
     found in any one-component-failed cell; the pre-fix design (`VyraPureEd`)
     is broken 200/200 once ML-DSA is Forgeable [fi].
   - **Excluded:** an oracle that signs under the composite's **own** context
     (`"VYRA-SIG-v1" ‖ suite_id`). By definition its output is a composite
     half, so the game refuses that query. A deployment that lets the same
     component key sign arbitrary caller-chosen contexts in its context mode
     (FIPS 204/205 context or Ed25519ph context) can be made to produce a
     composite half; with the other component broken, that completes a
     forgery. Component keys should therefore not be used outside the
     composite (defence in depth).
5. **Context-binding contract.** Separation depends on each component actually
   honouring the context. A component that ignores the context makes its half
   a standalone signature: the ContextIgnoring model breaks STRIP-COMPOSITE in
   the experiment even for `Vyra` [fi]. `CompositeComponent::context_bound` is
   a declared contract checked by tests for the named suites; the engine does
   not enforce it for custom assemblies.
6. **Cross-suite secret keys (raw interface).** Transition secret keys are 64
   bytes in every transition suite. A relabelled *wire* key is rejected by the
   check value [test]; a *raw* key used under another transition suite signs
   with the same Ed25519 key and an unrelated ML-DSA key (FIPS 204 key
   generation depends on the parameter set [from memory — verify]). The suite
   byte is in `M'` and in the composite context, so such reuse is domain
   separated; no analysis exists.
7. **Public-key canonicity.** Composite public keys are validated at parse and
   inside every verification (`docs/SPEC.md` §7.6): Ed25519 part canonical,
   not small order, in the prime-order subgroup; ML-DSA and SLH-DSA parts
   canonical by construction [test: `pk_validation.rs`, including
   `canonical_mixed_order_keys_rejected` (plain `ed25519-dalek` 3.0 accepts all
   7 constructed `A + T` keys and does not flag them weak; VYRA rejects them)
   and `standalone_adapter_rejects_mixed_order_keys_that_dalek_accepts`]. What
   remains: the subgroup check relies on curve25519-dalek's `is_torsion_free`
   (tested, not reviewed), and VYRA's rule is stricter than plain
   `verify_strict`, so other Ed25519 verifiers may accept keys VYRA rejects.
8. **VYRA-SIG-2 / VYRA-SIG-PQ1 public-key length coincidence** (1344 bytes):
   a relabelled public key parses but fails closed, because the suite id is in
   `M'`, in the context and in the public-key digest, and signature lengths
   differ (`docs/SPEC.md` §7.7).

## The sealed box argument

- **KEM-DEM [lit].** Hybrid encryption from an IND-CCA2 KEM and a one-time
  secure authenticated-encryption DEM yields IND-CCA2 public-key encryption
  (Cramer–Shoup 2003 [from memory — verify exact theorem]; the same pattern
  underlies HPKE base mode, RFC 9180).
- **VYRA instantiation [sketch].** The DEM key and nonce are
  `SHAKE256(0x01 ‖ frame("VYRA-SEAL-v1") ‖ frame([suite]) ‖ frame(K) ‖
  frame(kem_ct))[0..44]`. With `K` pseudorandom (from the KEM) and SHAKE256 a
  PRF/RO keyed by `K`, the (key, nonce) pair is pseudorandom and fresh per seal.
  ChaCha20-Poly1305 is used once per key, which is the setting in which one-time
  AEAD security is needed; the nonce adds nothing beyond determinism here.
- **Single use is load-bearing.** If two seals produce the same `K` (repeated
  entropy, see Randomness), they reuse key and nonce: XOR of the two
  plaintexts is revealed and Poly1305 forgeries become possible.
- **No sender authentication.** Anyone can seal to a public key. "Integrity"
  means: nobody without the recipient key can modify a sealed box (or its AAD)
  without detection; it does not identify the sender.
- **No forward secrecy** with a static recipient key (D-03).
- Not proven for the exact encoding; the KDF's binding of `kem_ct` is
  redundant with the combiner and was not analysed separately.

## Failure-injection evidence

This is the project's main empirical result (D-16). It turns "the composition
survives one component yielding" into a falsifiable experiment. Source:
`crates/vyra-yield`; deterministic output: `results/yield-matrix.md` and
`results/yield-matrix.json` (schema `vyra-yield-matrix/2`), kept current by
gates Y1/Y2 (`docs/CHECKS.md`). **It is falsification evidence, not a proof.**

### Design

- **Real composition code.** `Vyra` is the real `vyra_kem::combine`, run
  through `vyra_kem::CustomHybridKem`, and the real signature engine through
  `vyra_sig::CustomComposite` (descriptor id 0x7A; 0x7B for the cross-suite
  target). Tests show the assemblies equal the named suites byte for byte over
  real components (`vyra_assembly_over_real_components_is_vyra_kem_1`,
  `vyra_assembly_equals_named_transition_suite`,
  `vyra_assembly_equals_named_dual_pq_suite`).
- **Components.** KEM: ML-KEM-512 and HQC-128 through VYRA's adapters (the
  components of VYRA-KEM-1). Signatures: ML-DSA-44 + Ed25519 (VYRA-SIG-2
  components) and ML-DSA-44 + SLH-DSA-SHAKE-128s (VYRA-SIG-PQ1 components),
  real SLH-DSA, no stand-in.
- **Failure models (intentionally insecure wrappers of the real components).**
  KEM: `Leaky` (key is a public hash of pk and ct), `Malleable` (an extra
  ciphertext byte is ignored), `KeySubstitutable` (keys carry an ignored tag:
  MAL-BIND-K-PK failure), `Constant` (key is a public constant),
  `SenderKeyed` (the encapsulator chooses the key: HON-BIND failure).
  Signatures: `Forgeable` (a public tag always verifies), `Malleable` (an
  ignored extra byte), `KeySubstitutable` (ignored key tag: exclusive
  ownership), `ContextIgnoring` (the half is a default-mode standalone
  signature), `MessageCollapsing` (signs a 12-bit digest). A test checks that
  every model keeps correctness and breaks what it says it breaks
  (`models_break_what_they_say`, `models_keep_correctness_and_break_what_they_say`).
- **Comparison designs (KEM).** `Naive` = `SHA3-256(k1 ‖ k2)` (the research
  report's combiner); `Xor` = `k1 XOR k2`; `CtBound` = `H(k1, k2, c1, c2)`
  (ciphertexts only); `XWingStyle` = `H(k1, k2, c2, pk2)` — *in the style of*
  X-Wing (hashes only component 2's ciphertext and public key, here HQC's); it
  is **not** X-Wing. **Comparison designs (signatures).** `Concat` (both sign
  M in default mode), `ConcatCtx` (both sign a context-framed message, no
  public-key binding), `Either` (VYRA's representative, but OR-verification),
  and `VyraPureEd` (VYRA with the pre-fix PureEd25519 half).
- **Games.** KEM: IND-CCA2 (decapsulation oracle refuses only the challenge
  ciphertext) and the binding games X-BIND-K-CT / X-BIND-K-PK for X ∈ {HON,
  LEAK, MAL} as defined by Cremers–Dax–Medinger and restated by
  Krämer–Struck–Weishäupl (MAL only in their scenario I, Decaps–Decaps).
  Signatures: EUF-CMA and SUF-CMA; S-CEO and MBS as restated by Düzlü–Fiedler–
  Fischlin from the BUFF paper (Cremers et al., S&P 2021); and four games
  defined by this project: STRIP-COMPOSITE, STRIP-STANDALONE (standalone
  signing oracles on both component keys in four modes, §"The composite
  signature argument", gap 4), MIX (halves of two signers under a mixed key),
  CROSS-SUITE / CROSS-CONTEXT.
- **Adversaries.** Concrete strategies, one or more per game (e.g.
  `MaulReplay`, `MixAndMatch`, `Recompute`, `SecondCiphertext`, `CrossKey`;
  `Forge`, `Maul`, `StripHalf`, `Recombine-*`, `MixHalves`, `Relabel`,
  `SwapContext`). Binding and separation adversaries try every subset of
  components (RULES 26).
- **Statistics.** Master seed `VYRA-YIELD-U11`; every trial seeded from its cell
  label; one-sided exact binomial test of `H0: p ≤ baseline` (IND-CCA2: 1/2;
  binding and signature games: 2^-128); **BROKEN iff p < 10^-6**, otherwise
  **NO ATTACK FOUND** (never "secure"); 99% Wilson intervals. Trials per cell:
  KEM 200; transition signatures 200; dual post-quantum signatures **12**.
  Cells: 1955 (KEM) + 1410 (signatures) = 3365.
- **Controls.** Positive: both KEM components confidentiality-broken → every
  combiner BROKEN in IND-CCA2 (control A); Naive over Constant × Constant →
  every binding game BROKEN (A2); both signature components Forgeable → Forge
  wins EUF-CMA against every composition (S-A); `Either` with one Forgeable
  component → BROKEN (S-C); `VyraPureEd` with Forgeable ML-DSA → BROKEN in
  STRIP-STANDALONE (S-E). Named insecure baselines: `Naive` with one Malleable
  component (D-01) and `Xor` over two real components (theory: XOR is not
  IND-CCA2 even over two IND-CCA2 KEMs). Negative/trivial: CoinFlip and
  Garbage never win (D, S-D); both components real → no win (B, S-B, with
  by-design weaknesses of the comparison designs named). Calibration:
  CoinFlip vs Vyra over two real KEMs, 2000 trials, 1023 wins, verdict NO
  ATTACK FOUND; Garbage vs Vyra in EUF-CMA, 2000 trials, 0 wins.
- **Expectation rule.** Every cell carries `expected` (BROKEN, NO ATTACK FOUND
  or UNSPECIFIED) and `expected_basis`, which must name a claim, control or
  theory and follow the project's documented claim, never the observed result
  (RULES 35). Gate Y2 fails if any judged cell contradicts its expectation.
  Result: no cell contradicts its expectation.

### Results: KEM (200 trials per cell)

| Design | Observation | Basis |
|--------|-------------|-------|
| `Naive` `SHA3-256(k1 ‖ k2)` | **BROKEN** in IND-CCA2 (advantage 1.00) with one `Malleable` component, by mauling that side (`MaulReplay`); also with one `Constant` component. Also BROKEN in HON/LEAK/MAL-BIND-K-CT with one Malleable, Constant or SenderKeyed component | D-01 counterexample (expected) |
| `Xor` `k1 XOR k2` | **BROKEN** in IND-CCA2 even over **two real components** (`MixAndMatch`, advantage 1.00) | theory:XOR (expected) |
| `CtBound` `H(k1, k2, c1, c2)` | no attack found in IND-CCA2 and K-CT games with one failed component; **BROKEN in MAL-BIND-K-PK** with one `KeySubstitutable` or `Constant` component (`CrossKey`), and in HON/LEAK-BIND-K-PK over Constant × Constant | observation (UNSPECIFIED) |
| `XWingStyle` `H(k1, k2, c2, pk2)` | survives failures of the hashed component 2; **BROKEN** when the unhashed component 1 is `Malleable` or `Constant` (IND-CCA2), `Malleable`, `Constant` or `SenderKeyed` (HON/LEAK/MAL-BIND-K-CT), or `KeySubstitutable`, `Constant` or `SenderKeyed` (MAL-BIND-K-PK) | observation (UNSPECIFIED); consistent with X-Wing relying on a property of its unhashed ML-KEM component |
| **`Vyra`** | **no attack found in every cell with exactly one failed component** (230 cells, every model, every game, every adversary: claim check V1); BROKEN in IND-CCA2 only when **both** components lose confidentiality (Leaky × Leaky, Constant × Constant, Leaky × Constant: claim V2, by `Recompute`); **no attack found in every binding game even with both components broken** | claim:V1, claim:V2 (expected); binding with both broken is an observation |

### Results: signatures

| Observation | Pair, N | Basis |
|-------------|---------|-------|
| `Either` (OR-verification) is BROKEN in EUF-CMA with one Forgeable or MessageCollapsing component, and in SUF-CMA even over two real components | transition, 200 | control S-C (expected) / observation |
| `Concat` and `ConcatCtx` are BROKEN over two real components in STRIP-COMPOSITE, STRIP-STANDALONE and MIX; `Concat` also in CROSS-SUITE and CROSS-CONTEXT; both in S-CEO with one KeySubstitutable component | transition 200; dual-PQ 12 | control S-B by-design weaknesses (expected) / observation |
| **Before/after the Ed25519 fix:** `VyraPureEd` (PureEd25519 half) is BROKEN in STRIP-COMPOSITE in every pattern (the Ed25519 half is a standalone signature) and, once ML-DSA is Forgeable, BROKEN 200/200 in STRIP-STANDALONE by an adversary with a standalone Ed25519 signing oracle on the same key (all four `Recombine-*` modes). `Vyra` (Ed25519ph under the composite context): no attack found in either game in every one-component-failed pattern, except STRIP-COMPOSITE with a ContextIgnoring component (below) | transition, 200 | control S-E (expected); claim:yield-forgeable, claim:separation (expected) |
| `Vyra` with exactly one Forgeable component: no win in EUF-CMA, STRIP-STANDALONE (all oracle modes), MIX, S-CEO, MBS, CROSS-SUITE, CROSS-CONTEXT | transition 200; dual-PQ 12 | claim:yield-forgeable (expected) |
| `Vyra` with one Malleable or Forgeable component: **SUF-CMA BROKEN** (`Maul`). This is the documented gap 3, not a new weakness | transition, 200 | claim:SUF-gap3 (expected) |
| `Vyra` with one ContextIgnoring component: **STRIP-COMPOSITE BROKEN** (that half is a standalone signature). This is why context binding is a tested contract | transition 200; dual-PQ 12 | observation |
| `Vyra` dual-PQ pair (Real, Forgeable or ContextIgnoring on either side): no attack found except STRIP-COMPOSITE with ContextIgnoring | dual-PQ, 12 | claim checks (expected); weak evidence at N = 12 |

### What this does and does not show

It shows, reproducibly, that VYRA's composition code defeats every
implemented attack in every cell where exactly one component fails under the
modelled failures, while named insecure baselines in the same harness are
broken. It does **not** show:

- **security**: NO ATTACK FOUND means only that the implemented strategies did
  not win; attacks not implemented are not excluded;
- anything about **real failures**: the failure models are idealised; a real
  cryptanalytic break of ML-KEM, HQC, ML-DSA, SLH-DSA or Ed25519 will fail in
  its own way;
- anything about **real-component binding**: the real components are
  attacked only through the modelled failures. In particular the negative
  control B ("both real → no win against Naive, CtBound, XWingStyle, Vyra" in
  the binding games) cannot fail except through a harness bug, because no
  adversary targets real ML-KEM or HQC binding weaknesses; it says nothing
  about the binding properties of the real components, which the literature
  analyses separately (Schmieg 2024 for ML-KEM's MAL-BIND properties with
  expanded keys; Krämer–Struck–Weishäupl for HQC as of their analysis — the
  HQC version they analysed and its relation to v5.1 is to be verified);
- **small advantages**: with 200 trials a BROKEN verdict in IND-CCA2 needs at
  least 134 wins (advantage ≥ 0.34), so only gross attacks are detectable;
  almost all implemented attacks either win always or have no advantage (two
  BROKEN search-game cells, both against comparison designs under the
  deliberately weak MessageCollapsing model, were won once in 200 trials);
- **quantum** adversaries, **side channels**, multi-user settings, key-reuse
  settings beyond STRIP-STANDALONE (which excludes the composite's own
  context by definition);
- strong evidence for the **dual post-quantum** pair: 12 trials per cell
  (SLH-DSA signing takes seconds), Vyra and Concat only;
- anything about cells marked UNSPECIFIED as predictions: 2606 of 3365 cells
  carry no expectation (mostly comparison designs and both-components-failed
  patterns); their verdicts are observations, not pre-registered tests;
- a **proof**: it complements, and does not replace, the cited GHP18 theorem
  and the unreviewed sketches in this document.

## Machine-checked properties

VYRA's own encodings (wire header, bounds-checked reader, transcript framing,
constant-time equality's functional behaviour, the entropy adapter's failure
latching, and the signature message layout) are checked by machine within
exactly stated finite domains and bounds (D-18). None of this covers SHA-3,
the component algorithms, timing, zeroization, or content beyond the stated
domains. Elsewhere in this document "machine-checked" refers to this section.

### Exhaustive enumeration [enum] — run, pass

Source: `crates/vyra-proofs/tests/exhaustive.rs` (`cargo test -p vyra-proofs`,
runs on any host); described in `tools/kani/RESULTS.md`.

| Test | Property | Exact domain |
|------|----------|--------------|
| `decode_matches_spec_exhaustive` | wire `decode` equals a reference decoder (success condition, suite byte, payload subslice, error class) | all 7 object types × every string of length 0..=2, and every length-7/8 input whose header differs from the canonical header in ≤ 2 positions (each over all 256 values) |
| `reader_matches_model_exhaustive` | `Reader` matches its model; `finish` Ok iff all consumed | input length 0..=8 × every 4-operation sequence over {take(0..=9), take(usize::MAX), take(usize::MAX−1), remaining, rest} |
| `round_trip_exhaustive` | encode layout and round trip iff object types are equal | 49 type pairs × 256 suite bytes × payloads of length 0..=1 (3,223,808 cases) |
| `framing_injective_exhaustive` | no two (label, fields) sequences share a framed encoding; the reference parser is a left inverse on the same domain | (A) all byte values: label length ≤ 1, ≤ 1 field of length ≤ 1 (66,306 sequences); (B) alphabet {00, 01, 02, 08, FF}: label length ≤ 2, ≤ 3 fields of length ≤ 2 (954,304 sequences) |
| `ct_eq_exhaustive` | `ct_eq` equals equality | all pairs of length ≤ 1 over all bytes; all pairs of length ≤ 2 over a 16-value alphabet |
| `rng_adapter_exhaustive` | `RandCoreRng` failure latching | every 4-call sequence over {u32, u64, fill 0/1/2/3/8} × all 16 failure patterns |
| `sig_reference_parser_sanity` | the signature reference parser used by the Kani harness rejects short or mislabelled strings and splits a hand-built representative correctly | sanity test only, not a check of the layout |

Host mutation check (`tools/kani/exhaustive-mutants.sh`): 11 mutants of
`vyra-core`; 10 are killed. **M8 (the length prefix keeps only its low byte)
survives these host tests** because every length they reach is below 256. It
is killed by the model checker (lemma 1 below).

### Bounded model checking (Kani) [bmc] — STATUS (update this subsection only)

> **Source: `results/kani-report.txt` (date 2026-11-19T07:28:08Z; `===== SUMMARY =====`
> block; `overall exit status: 0`) and `tools/kani/RESULTS.md` (status
> 2026-11-19). This subsection is the only place in this document that states
> Kani results.**

**Result: all 10 entries (413 harnesses) SUCCESSFUL; all 12 mutants killed,
each by a property assertion.** A mutant counts as killed only if a property
check fails; a failure that is only an unwinding assertion would count as an
unexpected outcome.

Tooling: Kani 0.68.0, CBMC 6.11.0, SAT solver CaDiCaL (Kani default); image
`vyra-kani:0.68.0`, id `sha256:2dbdef80e322f20b4c274882069e090e7f2326328ef6dbcb54d3e782650f1ec0`,
built from `rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea`;
run by `tools/kani/run.ps1` (or `run.sh`). Runtime: 1079 s end to end, of
which about 800 s verification (10 entries, plus 12 mutants). Entries marked
`*` consist of one harness per **shape** (every combination of concrete lengths
up to the bound, with fully symbolic contents); the union of the shapes is
exactly the bounded domain.

| Entry | Property | Exact bound | Harnesses | Result | Mutant killed |
|-------|----------|-------------|-----------|--------|---------------|
| `wire_decode_exact` | P1: `wire::decode` total; Ok exactly when magic, version, type match; returns `input[6]` and exactly `input[7..]`; otherwise the exact error class | input length 0..=24, all byte values, all 7 expected types | 1 | SUCCESSFUL | M1 |
| `wire_reader_ops` | P1: every `Reader` op total; `take(n)` for any `usize` n returns exactly the next n bytes or the exact error with the reader unchanged; `finish` Ok exactly when all bytes consumed | input length 0..=64, up to 5 ops | 1 | SUCCESSFUL | M2, M3 |
| `wire_round_trip` * | P2: `encode` layout exact; `decode(encode(t,s,p),u)` is `Ok((s,p))` exactly when `t == u`, else the exact error | payload length 0..=16, all byte values, all suite bytes, all 49 (t,u) pairs | 17 | SUCCESSFUL | M4 |
| `wire_header_rejection` | P2: decode Ok exactly when magic, version and type bytes are canonical (all 2^56 header values symbolically) | payload length 0..=4 | 1 | SUCCESSFUL | M5 |
| `transcript_prefix_inverse` | P3.1: `prefix_len(frame_prefix_of_len(n)) == Some(n)`; `frame_prefix(x) == frame_prefix_of_len(len x)` | **every `usize` n**; x length ≤ 2 | 1 | SUCCESSFUL | M8 |
| `transcript_single_frame` | P3.2: `take_frame(push_frame(x) ‖ rest) == Some((x, rest))` as exact subslices | len(x) ≤ 16, len(rest) ≤ 16, all byte values | 1 | SUCCESSFUL | M6 |
| `transcript_framing_shape` * | P3.3: an independent reference parser recovers (label, fields) from `framed_encoding`, hence injectivity | label length ≤ 3; 0..=3 fields of length ≤ 3; all byte values | 340 | SUCCESSFUL | M7 |
| `secret_ct_eq_correct` | P4: `ct_eq` equals byte equality in both orders; no panic on unequal lengths | lengths 0..=8 each, all byte values | 1 | SUCCESSFUL | M9 |
| `rng_adapter_latches_failure` | P5: `RandCoreRng` never panics; outputs equal the source's bytes before a failure, all zero from the failing call on; source never called again; `finish` errors exactly when some call failed | ≤ 4 calls of u32/u64/fill (buffer ≤ 8 bytes); every success/failure pattern; arbitrary bytes written on failure | 1 | SUCCESSFUL | M10, M11 |
| `sig_message_representative` * | P6: the real `vyra_sig::message_representative_with_digest` succeeds, its 44-byte prefix `"VYRA-SIG-v1" ‖ suite ‖ digest` is at fixed offsets, and a reference parser recovers exactly (suite, digest, context, message), hence injectivity | context length 0..=6, message length 0..=6, all suite bytes, all 2^256 digests, all byte values | 49 | SUCCESSFUL | M12 |

**What the framing result (P3) states — three lemmas:**

1. **Prefix arithmetic, for every `usize` length n:** the 8-byte prefix
   `frame_prefix_of_len(n)` decodes back to n. The prefix encoding is therefore
   injective for all lengths. This is what kills M8, which survived every
   bounded content check (host enumeration and earlier bounds alike).
2. **Single frame:** for |x| ≤ 16 and |rest| ≤ 16, `take_frame` applied to
   `push_frame(x) ‖ rest` returns exactly `(x, rest)`.
3. **Whole encoding:** for label length ≤ 3 and ≤ 3 fields of ≤ 3 bytes, an
   independent reference parser (`vyra_proofs::reference::parse_framed`) is a
   left inverse of `framed_encoding`, which implies injectivity on that
   domain: same label, same number of fields, same bytes.

Extension of lemmas 2–3 beyond their bounds is a **hand argument**, not
machine-checked: the parser reads the length, which lemma 1 proves correct for
every length, and splits there. `Transcript` hashes exactly `framed_encoding`
(host known-answer test `transcript_hashes_exactly_framed_encoding`).

**Not covered:** SHA3-256 / SHAKE256 (assumed collision resistant); the
component algorithms; timing and constant-time behaviour; **zeroization** (the
`ct_eq` harness skips `Drop` with `mem::forget`, because zeroize's
inline-assembly optimisation barrier is not supported by Kani); payload checks
owned by vyra-kem / vyra-sig / vyra-seal; `RandCoreTryRng`; the public-key
digest; content beyond each bound (e.g. signature contexts of 7..=255 bytes,
which the function accepts).

**Diagnosis of the earlier FAILED results (first run, report of
2026-11-19T04:42:34Z).** No counterexample to any property was found in any
run. `wire_reader_ops` and `wire_round_trip` failed only on "unwinding
assertion loop 0": comparing `&'static str` values inside error values (e.g.
the 14-byte `"trailing bytes"`, the 22-byte `"unexpected object type"`) needs
more loop unwindings than the harnesses allowed; raising the bounds fixed
them without library changes. With symbolic slice lengths, `wire_round_trip`,
the framing proof and P6 then exhausted memory in CBMC (about 28–31 GB); this
was solved by enumerating concrete length **shapes** with symbolic contents
(the `*` entries). The `secret_ct_eq_correct` harness hit Kani's unsupported
inline assembly in zeroize's barrier through `Drop`, handled as above.

## Side channels

### What VYRA's own code does [inspection, test]

- Secret types (`SecretBytes`, `HybridSecretKey`, `CompositeSecretKey`, the
  DEM key, `OneShot` hedging buffer, transcript hash state through the
  `zeroize` features of `sha3`/`shake`) are zeroized on drop; `Debug` prints
  `[REDACTED]`; secret types have no `PartialEq` and compare with `subtle`'s
  constant-time equality (gate S9; the zeroize and redaction parts are tested,
  constant-time comparison is checked by inspection).
- No secret-dependent branches or secret-indexed memory accesses in VYRA glue
  code [inspection only, no tooling].
- KEM decapsulation always runs both components before inspecting either
  result; composite verification always runs both verifiers and combines with
  a non-short-circuiting `&`.
- Errors are uniform: `VerificationFailed` without naming the failing
  component; `DecryptionFailed` without detail; implicit rejection in the KEM.
- Buffers holding secrets are allocated with exact capacity to avoid
  reallocation leaving unzeroized copies. The sealed-box output buffer is a
  zeroizing buffer from before the plaintext is copied in, so an error path
  after the copy no longer leaves plaintext in freed memory (RULES 16).
- Secret-key check values are recomputed and compared in constant time, and
  the computed value is zeroized afterwards.

These properties are established by code inspection and project-internal
review only. No ctgrind/Binsec analysis has been performed; the only timing
measurement is the coarse HQC smoke test described below.

### The HQC port (`vyra-hqc`) [inspection, smoke test]

`vyra-hqc` is VYRA-maintained code, so its side-channel behaviour is VYRA's
responsibility, not an inherited upstream claim.

- **Carry-less multiplication.** Upstream `hqc-kem`'s `unsafe` PCLMULQDQ path
  and its portable fallback (a window-table kernel whose table loads were
  indexed by secret operand bits) are **removed**. The default kernel
  (`clmul_int` in `src/poly.rs`) is branch-free and table-free, built from
  integer multiplications of masked operands (after BearSSL's
  `ghash_ctmul64.c`). It is constant time **only if the CPU's 64×64→128-bit
  integer multiplier is constant time**: true on current x86-64 and AArch64
  cores per the crate's notes, not guaranteed on every target (some cores have
  early-terminating multipliers). The cargo feature `bitserial-mul` selects a
  multiplier-free shift-and-XOR kernel for such targets (slower). Both kernels
  are tested against a naive bit-by-bit product.
- **Other touched code:** the rewritten Reed–Solomon decoder follows the v5.1
  reference's constant-time structure (mask-based selection, public loop
  bounds, `core::hint::black_box` where the reference uses an optimisation
  barrier; table loads indexed by public exponents only). The FO ciphertext
  comparison and the real/rejection key selection are upstream's constant-time
  code, unchanged. Decapsulation derives the key pair from the seed **once**.
- **Timing smoke test (not a constant-time proof).** The dudect-style Welch
  t-tests in `vyra-hqc/tests/ct.rs` (manual, `#[ignore]`d) were run once on one
  machine: decapsulation of valid versus corrupted ciphertexts and key
  generation across two fixed seeds, all three parameter sets, gave |t| below
  1.6 (docs/ATTEMPTS.md, U10-R1). The samples are small (1500–3000 per class),
  wall-clock based, from a single machine; dudect practice uses far larger
  samples, and a small |t| shows only that no gross leak appeared in this run.
- **Lint relaxation.** Seven forked arithmetic modules (`kem.rs`, `pke.rs`,
  `poly.rs`, `code.rs`, `reed_solomon.rs`, `reed_muller.rs`, `sampling.rs`)
  allow `clippy::indexing_slicing` in source, so gate S8 ("no panics in library
  code") is **not** evidence for them; robustness evidence for parsing and
  decapsulation there is the KATs plus VYRA's fuzz/property and tamper tests.

### Inherited and unmeasured

- **Upstream timing is inherited and unmeasured** (D-05). Statements from the
  upstream crates are their claims, not VYRA results:
  - `ed25519-dalek` README states signing is constant-time. Verification is
    variable-time, which is acceptable because its inputs are public.
  - `chacha20poly1305` README: constant time only on CPUs with constant-time
    multiplication for the portable backend.
  - `ml-kem` and `ml-dsa` READMEs make no constant-time claim that VYRA relies
    on, and state they were never independently audited.
  - `fips205` 0.5.0 README (quoted in `vyra-sig/src/slhdsa.rs`): "Key
    generation and signing are constant-time: every branch, loop bound and
    memory index depends only on public data". This is upstream's claim; VYRA
    has not verified it.
  - `ed25519-dalek` makes no separate statement that VYRA found about the
    Ed25519ph path (`sign_prehashed`); its constant-time statement is about
    signing in general.
- **ML-DSA signing** has a rejection-sampling loop whose iteration count
  depends on secret data and the message; FIPS 204 signing is variable-time by
  design [from memory — verify FIPS 204 guidance on this].
- **HQC** key generation uses rejection sampling for fixed-weight vectors
  (unchanged from upstream). The upstream note kept in `tests/ct.rs` argues
  that the rejection pattern reveals nothing about the accepted positions;
  VYRA has not verified that argument. Because the stored key is the seed
  (D-13, now also the v5.1 default format), this key generation runs on
  **every** HQC decapsulation, which multiplies the number of secret-dependent
  executions an observer can measure.
- **Key expansion on every private operation (D-12, D-13).** Every hybrid
  decapsulation re-runs `ML-KEM.KeyGen_internal(d, z)` and the full HQC key
  generation from `seed_kem` (both public keys are re-derived for the
  combiner); every ML-DSA signature re-expands ξ; every SLH-DSA signature
  recomputes `PK.root` (a full top-tree key generation) from the stored seeds,
  and composite signing additionally re-derives both public keys (for SLH-DSA
  that is a second key generation per signature). Each is an additional
  secret-dependent computation exposed to timing and physical leakage, and a
  measurable cost (see `results/benchmarks.md`).
- **FO re-encryption.** The FO transform's re-encryption step can act as a
  plaintext-checking oracle under power/EM leakage (Ravi et al., TCHES 2020;
  Ueno et al., "Curse of Re-encryption", TCHES 2022 — the latter lists Kyber
  and HQC among affected schemes) [verified online]. This risk lives inside the
  components, is out of scope, and VYRA has no countermeasure (D-04).
- **Rust/LLVM** give no constant-time guarantee; the optimiser may introduce
  branches into branch-free source.
- **Zeroization is best-effort:** moves and copies of stack values,
  upstream-internal temporaries, registers, swap, core dumps and hibernation
  files are not covered; callers can copy secrets out with `expose`.
  `SecretBytes::from_slice` copies; the caller's original is not zeroized.
- **No masking, no fault protection** (D-05). No leakage-resilience claim.

## Randomness

### Entropy per operation (exact; asserted by tests)

| Operation | Bytes drawn | Order | Test |
|-----------|-------------|-------|------|
| VYRA-KEM KeyGen (all suites) | 96 | ML-KEM `d‖z` 64, HQC `seed_kem` 32 | `vyra-kem/tests/entropy.rs` |
| VYRA-KEM-1 Encaps / Seal | 64 | ML-KEM `m` 32, HQC `m` 16 + salt 16 | same |
| VYRA-KEM-3 Encaps / Seal | 72 | 32, then 24 + 16 | same |
| VYRA-KEM-5 Encaps / Seal | 80 | 32, then 32 + 16 | same |
| Decaps / Open | 0 | — | inspection |
| VYRA-SIG-2/3/5 KeyGen | 64 | ML-DSA ξ 32, Ed25519 seed 32 | `vyra-sig/tests/entropy_sweep.rs` |
| VYRA-SIG-2/3/5 Sign | 32 | ML-DSA `rnd` (Ed25519ph deterministic) | same |
| VYRA-SIG-PQ1/PQ3/PQ5 KeyGen | 80 / 104 / 128 | ML-DSA ξ 32, then SLH-DSA `SK.seed ‖ SK.prf ‖ PK.seed` 3n in one request | same |
| VYRA-SIG-PQ1/PQ3/PQ5 Sign | 48 / 56 / 64 | ML-DSA `rnd` 32, then SLH-DSA `addrnd` n | same |
| VYRA-SIG Verify | 0 | — | same |

The tests feed sources that fail after `N` bytes for every `N` across the range
and check that each operation returns `Ok` exactly when it received all its
bytes and `EntropyFailure` otherwise [test]. On failure, no partial output is
returned; `RandCoreRng` zero-fills after a failure and the result is discarded.

### Consequences of RNG failure or repetition

| Primitive | Effect of predictable or repeated entropy |
|-----------|-------------------------------------------|
| KEM KeyGen | predictable entropy ⇒ secret key known to the attacker; repeated entropy ⇒ two parties share a key pair |
| ML-KEM / HQC Encaps | repeated `m` (and salt) to the same key ⇒ identical ciphertext and identical component key; predictable `m` ⇒ that component's shared secret is known. The combiner still protects `K` if the **other** component's randomness is good |
| Sealed box | repeated encapsulation randomness to the same key ⇒ same `K` ⇒ same AEAD key **and nonce**: catastrophic for ChaCha20-Poly1305 (plaintext XOR leaks, forgeries) |
| ML-DSA Sign | a *reported* failure makes VYRA return `EntropyFailure` (no signature). An *unreported* repeated or predictable `rnd` degrades hedged signing to the behaviour of deterministic ML-DSA (FIPS 204 also specifies a deterministic variant with a fixed `rnd`), which FIPS 204 treats as an acceptable mode [from memory — verify]; the extra protection that hedging gives against fault and some side-channel attacks is lost |
| SLH-DSA Sign | hedged: a *reported* failure returns `EntropyFailure`; an *unreported* repeated or predictable `addrnd` degrades to the deterministic variant (FIPS 205 uses `PK.seed` as `addrnd` there), which remains a specified mode; hedging's extra protection against fault and side-channel attacks is lost |
| SLH-DSA KeyGen | predictable entropy ⇒ key known (all 3n bytes are secret except `PK.seed`) |
| Ed25519 / Ed25519ph Sign | deterministic; no entropy used |
| Signature KeyGen | predictable entropy ⇒ key known |

- VYRA trusts the OS CSPRNG via `getrandom`; it cannot detect a CSPRNG that
  returns low-entropy bytes without signalling an error (e.g. early boot,
  cloned VM snapshots).
- `DeterministicEntropy` is **test-only**: whoever knows its seed knows every
  key. Reusing one seed for two seals reuses key and nonce.

## Key lifecycle

- **Generation:** from `OsEntropy` only; every component secret key is a
  key-generation seed (D-12, D-13): ML-KEM `d‖z` (64), HQC `seed_kem` (32),
  ML-DSA ξ (32), Ed25519 seed (32), SLH-DSA `SK.seed ‖ SK.prf ‖ PK.seed`
  (48 / 72 / 96, with `PK.root` recomputed on use). Hybrid KEM secret keys are
  96 bytes in every suite; composite signature secret keys are 64 bytes
  (transition) and 80 / 104 / 128 bytes (dual post-quantum).
- **Storage and serialization:** `to_bytes()` of secret keys returns zeroizing
  `SecretBytes` in the wire format: header ‖ seeds ‖ 16-byte check value
  (119 bytes for KEM keys; 87 for transition and 103 / 127 / 151 for dual
  post-quantum signature keys). There is **no** built-in
  protection at rest (no encryption, no password wrapping, no HSM support);
  the caller must provide it. The check value is not a MAC.
- **Validation on load:** wire secret keys are length-checked and their check
  value (bound to the suite id) is recomputed and compared in constant time,
  which rejects relabelled or corrupted keys. Every seed of the right length is
  a valid key, and all public data (both KEM public keys, both signature public
  keys) is re-derived from the seeds at use, so a stored secret key cannot
  contain a public key that contradicts it. Raw secret keys (trait-level API)
  carry no suite and are not checked.
- **Rotation:** VYRA has no rotation mechanism; suite ids and the wire version
  allow old and new keys to coexist. Rotate on any suspicion of compromise and
  whenever the HQC component is replaced (for example on migration to FIPS
  207, D-14).
- **Compromise consequences:** a compromised KEM secret key decapsulates **all**
  past and future ciphertexts to it (no forward secrecy with static keys,
  D-03); a compromised signature key forges arbitrary signatures until the key
  is revoked by a mechanism outside VYRA.
- **Ephemeral usage:** forward secrecy requires a fresh KEM key pair per session
  that is erased afterwards, plus a protocol that authenticates it. VYRA
  provides the primitives, not the protocol.
- **Destruction:** dropping the key objects zeroizes VYRA's buffers
  (best-effort, see Side channels); copies made by the caller, by the OS or in
  storage are the caller's responsibility.

## Limitations

1. **No security proof exists for VYRA's concrete instantiation** of the
   combiner, the composite signatures or the sealed box. The sketches in this
   document are unreviewed and list their own gaps.
2. **Failure injection is not a proof.** It tests idealised failure models
   against implemented adversaries only, detects only gross attacks (§Failure-
   injection evidence), has small N for the dual post-quantum pair, and does
   not model quantum adversaries, side channels or real cryptanalysis.
3. **Bounded and exhaustive machine checks cover only VYRA's own encodings
   within their stated bounds** (§Machine-checked properties). Framing
   injectivity beyond the bounded domain rests on a hand argument from the
   all-lengths prefix lemma. They say nothing about SHA-3, the components,
   timing or zeroization.
4. **No external review of any kind**: no independent cryptanalysis, no audit,
   no side-channel evaluation by anyone outside this project.
5. **VYRA maintains its own HQC implementation.** `vyra-hqc` is a fork of the
   `hqc-kem` release candidate modified to HQC v5.1 by the VYRA authors; its
   conformance evidence is the official v5.1 KATs alone (no independent second
   v5.1 implementation; the official KATs contain no invalid ciphertexts, so
   the implicit-rejection path has no external known answers). HQC is not yet
   a standard (FIPS 207 pending).
6. **Post-quantum signature cost.** Dual post-quantum signatures are 10276 /
   19533 / 34419 bytes and SLH-DSA "s" signing takes on the order of seconds
   (`results/benchmarks.md`); the hybrid KEM is slow because HQC runs without
   hardware carry-less multiplication. Large objects throughout (VYRA-KEM-5
   ciphertexts 15989 bytes raw; sealed boxes add up to 16012 bytes).
7. **Transition suites give no second line against a quantum adversary**
   (Ed25519 falls to Shor); their Ed25519ph half adds a SHA-512
   collision-resistance assumption for that half (D-17).
8. **Constant-time behaviour is unverified**: the HQC port rests on code
   structure, a CPU-multiplier assumption and one coarse smoke test; other
   upstream crates' timing is unmeasured; `fips205`'s constant-time statement
   is its own claim; Rust/LLVM give no guarantee; zeroization is best-effort;
   no masking or fault protection. Seed-only keys mean full key generation on
   every private operation (for SLH-DSA, twice per signature: once to derive
   the public key for `M'`, once inside signing).
9. Upstream crates `ml-kem`, `ml-dsa` (and the differential partner `slh-dsa`)
   state in their READMEs that they have never been independently audited. A
   clean `cargo audit` (2026-11-18) only means no *known* advisory matched.
10. Raw (trait-level) secret keys carry no suite; within the transition family
    a raw key used under another suite signs with the same Ed25519 key. Only
    typed objects and the wire form (check value, which is not a MAC) bind the
    suite.
11. Component separation in the signatures depends on each component honouring
    the composite context; this is a tested contract for the named suites, not
    enforced for custom assemblies. Component keys used elsewhere under the
    composite's own context can produce composite halves.
12. SUF-CMA of the composite needs both components SUF-CMA (observed in the
    failure-injection experiment).
13. Ed25519 key validation relies on curve25519-dalek's `is_torsion_free`
    (tested, not reviewed) and is stricter than plain `verify_strict`, so VYRA
    and other Ed25519 verifiers can disagree on keys no honest signer produces.
14. Not FIPS 140-validated, not CAVP-certified (running NIST ACVP vectors as
    tests is not certification), not interoperable with any standardised hybrid
    or composite (X-Wing, CFRG hybrid KEMs, RFC 10073).
15. No estimator runs; every security category is quoted from the component
    specifications.
16. Sealed box: no sender authentication, no forward secrecy, no replay
    protection, plaintext length revealed, single-shot in memory.
17. Protocol-level properties (identity, downgrade, replay) are not provided.

## Open questions

1. **Formal proof of VYRA's combiner** in the ROM and QROM for the exact
   encoding (label, suite id, public keys as extra inputs), including the
   binding notions of Cremers–Dax–Medinger (HON/LEAK/MAL-BIND-K-CT and -K-PK)
   for this combiner, the shared-SHA3-256 issue (input-length separation only),
   the SHAKE256 issue for the sealed-box KDF, multi-user tightness, and the
   extended key-reuse model of Millerjord–Stebila–Steckel.
2. **Composite signature proofs** for both families, written out: EUF-CMA if
   either component is (with the Ed25519ph SHA-512 delta), BUFF-style
   properties (S-CEO, MBS) and a non-separability notion covering the
   STRIP-STANDALONE oracle including the composite's own context.
3. **Unbounded encoding proofs**: extend the bounded framing and
   representative results (§Machine-checked properties) to unbounded proofs,
   e.g. in a proof assistant or a deductive verifier, replacing the current
   hand argument for long inputs; larger bounds for P6 (contexts up to 255
   bytes).
4. **Real-component binding properties**: establish, from the literature and
   by checking the implementations, which binding notions ML-KEM (seed-form
   keys, as VYRA stores them; cf. Schmieg 2024) and HQC v5.1 (cf.
   Krämer–Struck–Weishäupl, whose HQC version must be compared with v5.1)
   actually have, and add adversaries that target real-component binding
   weaknesses to the experiment.
5. **MAL binding scenarios II and III** (the experiment implements only
   scenario I, Decaps–Decaps).
6. **Larger-N dual post-quantum experiments** (12 trials per cell today) and
   the comparison designs other than Concat for that pair.
7. **Constant-time verification** of VYRA's glue, the HQC port and the
   upstream crates with tooling (dudect with large samples on several CPUs,
   ctgrind/Valgrind memcheck taint, Binsec/Rel, timecop); per-target
   confirmation of the HQC multiplier assumption.
8. **HQC**: FIPS 207 migration; an independent v5.1 implementation for
   differential testing (including rejection keys); replacing the port with an
   audited upstream crate.
9. **Context-variant choice for Ed25519**: move the Ed25519 half to Ed25519ctx
   (no prehash, removing the SHA-512 collision delta) if a reviewed
   implementation exposes it; a wire version bump would be required.
10. **Estimator runs**: lattice estimator for ML-KEM/ML-DSA; ISD estimator
    (including ePrint 2026/1498) for HQC v5.1.
11. **Fuzzing campaign** with coverage guidance beyond the property tests,
    in particular of the forked HQC modules that gate S8 does not cover.
12. **Multi-target margins** for the sealed box and the KEM.
13. The standardisation-level questions in §Suggestions for the field.

## Deviations from the research report

Full text with evidence: [`docs/DECISIONS.md`](DECISIONS.md).

| ID | One-line summary |
|----|------------------|
| D-01 | Report's `K = KDF(k1 ‖ k2)` is not CCA-robust; replaced by the GHP18-style combiner hashing suite, both secrets, both ciphertexts and both public keys (the experiment reproduces the break). |
| D-02 | Report's "Decaps returns ⊥ on invalid" contradicts ML-KEM/HQC; VYRA uses implicit rejection and errors only on malformed input. |
| D-03 | Report's forward-secrecy claim is wrong for static keys; the KEM alone provides none. |
| D-04 | POLKA dummy-ciphertext / rigidity countermeasures not implemented; no leakage-resilience claim. |
| D-05 | Masking, fault countermeasures and DPA testing not implemented; physical attackers out of scope. |
| D-06 | Security statements limited to NIST categories claimed by components; hybrid = minimum. |
| D-07 | Report table errors corrected (Falcon-512 category, ML-DSA assumptions, McEliece sizes, uncited cycle counts, HQC sizes from code). |
| D-08 | Signatures originally scoped to composite ML-DSA + Ed25519; the "not implemented" part for a hash-based second component is reversed by D-17; threshold and multi-party schemes remain out. |
| D-09 | "Leakage-resilient commitments" not implemented (no construction given). |
| D-10 | Implementation language Rust instead of C/Python; safe Rust only. |
| D-11 | **Resolved by D-14.** Recorded that HQC was pinned to a pre-standard snapshot whose parameters HQC v5.1 later raised. |
| D-12 | Secret keys stored as seeds where the standard allows (ML-KEM, ML-DSA). |
| D-13 | HQC secret key stored as its 32-byte key-generation seed (now the v5.1 compressed decapsulation key). |
| D-14 | HQC v5.1 through the in-tree port `vyra-hqc`; all official v5.1 KATs match; no independent v5.1 implementation; wire version byte stays 1, defined as the format at first publication. |
| D-15 | The name "Verified Yielding Resistance Architecture" defined word by word by its evidence, with explicit non-claims. |
| D-16 | Yielding resistance is tested by failure injection (`crates/vyra-yield`, `results/yield-matrix.*`): falsification evidence, not proof. |
| D-17 | Dual post-quantum suites VYRA-SIG-PQ1/PQ3/PQ5 (ML-DSA + SLH-DSA); the Ed25519 half is Ed25519ph under the composite context after failure injection found the standalone-oracle forgery; known 1344-byte public-key coincidence fails closed. |
| D-18 | Machine-checked properties of VYRA's own encodings: exhaustive enumeration and Kani harnesses with mutation checks, within stated bounds. |

## Evidence summary

Evidence kinds: proof in literature · proof sketch here · failure injection
(falsification against idealised failure models) · exhaustive enumeration
(every element of a finite domain) · bounded model checking (Kani, within a
bound) · test · inspection · none.

| Property | Supported by | Kind of evidence |
|----------|--------------|------------------|
| VYRA-KEM IND-CCA2 if one component is IND-CCA2 (ROM) | GHP18 for the technique; sketch above for VYRA's encoding; `Vyra` with one failed component: no attack found in 230 cells | proof in literature (technique) / proof sketch here / failure injection |
| VYRA-KEM IND-CCA2 in the QROM | Don–Fehr–Huang for GHP18's hash-based skPRF | proof in literature (related construction only) / none for VYRA |
| Naive `KDF(k1‖k2)`, XOR, ciphertext-only and X-Wing-style combiners fail under the modelled failures | `results/yield-matrix.md` | failure injection |
| KEM binding of `K` to ciphertexts, public keys, suite | SHA3-256 collision resistance; binding games: no attack found even with both components broken | proof sketch here (informal) / failure injection / test (S6) |
| ML-KEM IND-CCA2 under MLWE | FIPS 203 and its cited analyses | proof in literature |
| HQC-KEM IND-CCA2 under 2-DQCSD-P / 3-DQCSD-PT (ROM) | HQC spec v5.1 Thm 6.4 | proof in literature (that VYRA's port implements it rests on the KATs) |
| ML-KEM implemented correctly | IETF LAMPS example key; differential interop with `fips203` 0.5.0 | test |
| `vyra-hqc` implements HQC v5.1 | 100 official KAT counts per set via crate and adapter; 200 official Reed–Solomon vectors per set; negative control | test (official KATs only) |
| ML-DSA implemented correctly | NIST ACVP keyGen (75), sigGen (90; signing driven through upstream with expanded keys, signatures verified by VYRA's adapter), sigVer (45; through the adapter); differential interop with `fips204` 0.5.0 | test |
| SLH-DSA implemented correctly | NIST ACVP keyGen (30), sigGen (42, byte-exact through the adapter), sigVer (42) = 114 vectors through VYRA's adapter; differential tests against `slh-dsa` | test |
| Ed25519 / Ed25519ph implemented correctly | RFC 8032 §7.1 vectors 1–3; RFC 8032 §7.3 Ed25519ph vector through the half path; independent test-side reference on 24 context cases | test |
| Composite EUF-CMA if either component is (single key) | reduction sketch above; one Forgeable component: no attack found | proof sketch here / failure injection |
| Composite SUF-CMA | requires both components SUF-CMA; one Malleable or Forgeable component breaks it | none for VYRA (gap observed by failure injection) |
| No half is a standalone default-mode signature (all named suites) | composite context in every half; Ed25519ph | test (`separation.rs`) / failure injection (STRIP-COMPOSITE, STRIP-STANDALONE, four oracle modes) |
| Pre-fix PureEd25519 half was exploitable with a standalone oracle | `VyraPureEd` control: BROKEN 200/200 with Forgeable ML-DSA | failure injection |
| Cross-key / cross-suite / cross-context separation | `pk_digest`, suite byte, composite context, check value | test / failure injection (MIX, S-CEO, CROSS-SUITE, CROSS-CONTEXT) |
| Composite public-key validation (Ed25519 canonical, not small order, prime-order subgroup; ML-DSA, SLH-DSA canonical by construction) | code | test (`pk_validation.rs`: 40 enumerated non-canonical encodings, 7 mixed-order keys, standalone adapter) + inspection |
| Composite security against quantum adversaries | dual-PQ: ML-DSA or SLH-DSA; transition: ML-DSA alone | proof in literature (components) / none for the composites |
| KEM public-key validation (FIPS 203 modulus, HQC padding) | code | test |
| No stored public key can contradict the secret key (seed-form keys; SLH-DSA `PK.root` recomputed) | code | test + inspection |
| Wire secret keys bound to their suite | check value | test |
| Wire decoder, reader, framing, `ct_eq` (functional), entropy-adapter latching correct | `crates/vyra-proofs` | exhaustive enumeration (stated domains) + bounded model checking (Kani: all entries SUCCESSFUL within their bounds, all mutants killed); framing prefix arithmetic for every `usize` length; framing beyond the bounds by hand argument |
| Signature message-representative layout injective | the real `message_representative_with_digest` | bounded model checking (context and message lengths 0..=6, all suite bytes and digests; mutant M12 killed); beyond the bound by inspection |
| Implicit rejection, no secret-dependent error oracle in VYRA glue | code | test (S3) + inspection |
| HQC v5.1 / ML-KEM / ML-DSA / SLH-DSA parameters meet their categories | designers' claims | quoted claims; no estimator run (none) |
| `vyra-hqc` constant-time | branch-free, table-free kernel (CPU-multiplier assumption); smoke test, all \|t\| < 1.6 | inspection + one coarse timing smoke test (not a proof) |
| Constant-time behaviour of other upstream crates | upstream statements (`fips205`, `ed25519-dalek`, `chacha20poly1305`) | none (unmeasured; upstream claims) |
| Constant-time behaviour of VYRA glue | code reading | inspection |
| Zeroization and redaction of secret types | code; tests | test (S9) + inspection |
| Entropy-failure handling | sweep tests | test (T-4) |
| Parser robustness (no panic) | property tests | test (S1, S2, S10) |
| Dependencies free of known advisories | `cargo audit`, 2026-11-18 | point-in-time tool run |
| Sealed box IND-CCA2 | KEM-DEM composition theorem + VYRA-KEM | proof in literature (paradigm) / proof sketch here |
| Sealed box sender authentication; forward secrecy | — | none (not goals) |
| Resistance to physical side channels and faults | — | none (out of scope) |

## References

Each entry is marked **[verified online]** (bibliographic data checked on
2026-11-18 against the publisher, IACR ePrint, IETF datatracker or project
site) or **[from memory — verify]**.

- [FIPS202] NIST. *SHA-3 Standard: Permutation-Based Hash and
  Extendable-Output Functions.* FIPS PUB 202, 2015. [from memory — verify]
- [FIPS203] NIST. *Module-Lattice-Based Key-Encapsulation Mechanism Standard.*
  FIPS PUB 203, published 13 August 2024. [verified online: publication date,
  via secondary sources]
- [FIPS204] NIST. *Module-Lattice-Based Digital Signature Standard.* FIPS PUB
  204, published 13 August 2024. [verified online: publication date, via
  secondary sources]
- [HQC-SPEC] C. Aguilar Melchor et al. (HQC team). *HQC specifications,
  version 5.1*, dated 2026/10/12 and 2026/11/09, pqc-hqc.org. Assumptions
  2-DQCSD-P and 3-DQCSD-PT; IND-CCA2 in the ROM (Theorem 6.4); Table 8
  parameters and DFR; changelog v5.0 → v5.1. [verified online; author list
  from memory — verify]
- [NIST-HQC] NIST. *NIST Selects HQC as Fifth Algorithm for Post-Quantum
  Encryption.* News release, 11 March 2025. [verified online]
- [CHLT26] K. Carrier, V. Hatey, L. Luzzi, J.-P. Tillich. *Multilevel
  Amortized Gaussian Elimination in Information-Set Decoding: Applications to
  HQC and PCG.* Cryptology ePrint Archive, Paper 2026/1498. [verified online,
  as cited in HQC spec v5.1]
- [RFC8032] S. Josefsson, I. Liusvaara. *Edwards-Curve Digital Signature
  Algorithm (EdDSA).* RFC 8032, 2017. [from memory — verify]
- [RFC8439] Y. Nir, A. Langley. *ChaCha20 and Poly1305 for IETF Protocols.*
  RFC 8439, 2018. [from memory — verify]
- [RFC9180] R. Barnes, K. Bhargavan, B. Lipp, C. Wood. *Hybrid Public Key
  Encryption.* RFC 9180, 2022. [from memory — verify]
- [GHP18] F. Giacon, F. Heuer, B. Poettering. *KEM Combiners.* PKC 2018;
  Cryptology ePrint Archive, Paper 2018/024. [verified online]
- [DFH22] J. Don, S. Fehr, Y.-H. Huang. *Adaptive versus Static Multi-oracle
  Algorithms, and Quantum Security of a Split-key PRF.* TCC 2022; Cryptology
  ePrint Archive, Paper 2022/773. [verified online]
- [MSS26] L. Millerjord, D. Stebila, C. Steckel. *Split-key PRFs and Extended
  Hybrid Security for KEM Combiners.* IACR Communications in Cryptology, Vol. 2,
  No. 4, doi:10.62056/ah890lmol. [verified online]
- [BBFGS19] N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila.
  *Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange.*
  PQCrypto 2019, LNCS, doi:10.1007/978-3-030-25510-7_12; Cryptology ePrint
  Archive, Paper 2018/903. [verified online]
- [XWING] M. Barbosa, D. Connolly, J. D. Duarte, A. Kaiser, P. Schwabe,
  K. Varner, B. Westerbaan. *X-Wing: The Hybrid KEM You've Been Looking For.*
  IACR Communications in Cryptology, doi:10.62056/a3qj89n4e; Cryptology ePrint
  Archive, Paper 2024/039. [verified online]
- [CDM23] C. Cremers, A. Dax, N. Medinger. *Keeping Up with the KEMs: Stronger
  Security Notions for KEMs and Automated Analysis of KEM-based Protocols.*
  Cryptology ePrint Archive, Paper 2023/1933. [verified online; the ePrint page
  lists it as a preprint; later venue (ACM CCS 2024) from memory — verify]
- [CFRG-HKEM] D. Connolly, R. Barnes, P. Grubbs. *Hybrid PQ/T Key
  Encapsulation Mechanisms.* draft-irtf-cfrg-hybrid-kems-12, 6 July 2026,
  work in progress. [verified online]
- [RFC10073] M. Ounsworth, J. Gray, M. Pala, J. Klaußner, S. Fluhrer.
  *Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for Use
  in X.509 Public Key Infrastructure.* RFC 10073, November 2026 (formerly
  draft-ietf-lamps-pq-composite-sigs). [verified online, IETF datatracker]
- [POLKA] C. Hoffmann, B. Libert, C. Momin, T. Peters, F.-X. Standaert.
  *POLKA: Towards Leakage-Resistant Post-quantum CCA-Secure Public Key
  Encryption.* PKC 2023, LNCS, pp. 114–144, doi:10.1007/978-3-031-31368-4_5;
  Cryptology ePrint Archive, Paper 2022/873. [verified online]
- [RRCB20] P. Ravi, S. Sinha Roy, A. Chattopadhyay, S. Bhasin. *Generic
  Side-channel attacks on CCA-secure lattice-based PKE and KEMs.* IACR TCHES
  2020(3), pp. 307–335. [verified online]
- [UXTITH22] R. Ueno, K. Xagawa, Y. Tanaka, A. Ito, J. Takahashi, N. Homma.
  *Curse of Re-encryption: A Generic Power/EM Analysis on Post-Quantum KEMs.*
  IACR TCHES 2022(1), pp. 296–322. [verified online]
- [KLS18] E. Kiltz, V. Lyubashevsky, C. Schaffner. *A Concrete Treatment of
  Fiat-Shamir Signatures in the Quantum Random-Oracle Model.* EUROCRYPT 2018.
  [from memory — verify]
- [BCJZ21] J. Brendel, C. Cremers, D. Jackson, M. Zhao. *The Provable Security
  of Ed25519: Theory and Practice.* IEEE S&P 2021. [from memory — verify]
- [BHMS17] N. Bindel, U. Herath, M. McKague, D. Stebila. *Transitioning to a
  Quantum-Resistant Public Key Infrastructure.* PQCrypto 2017. [from memory —
  verify]
- [CS03] R. Cramer, V. Shoup. *Design and Analysis of Practical Public-Key
  Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack.* SIAM
  Journal on Computing 33(1), 2003. [from memory — verify]
- [Procter14] G. Procter. *A Security Analysis of the Composition of ChaCha20
  and Poly1305.* Cryptology ePrint Archive, Paper 2014/613. [from memory —
  verify]
- [Bernstein10] D. J. Bernstein. *Grover vs. McEliece.* PQCrypto 2010,
  pp. 73–80. [verified online, as cited in HQC spec v5.1]
- [DOOM] N. Sendrier. *Decoding One Out of Many.* PQCrypto 2011. [from memory —
  verify; cited as reference [40] in HQC spec v5.1]

- [FIPS205] NIST. *Stateless Hash-Based Digital Signature Standard.* FIPS PUB
  205, published 13 August 2024. [verified online: publication date, via
  secondary sources; title from memory — verify]
- [KSW25] J. Krämer, P. Struck, M. Weishäupl. *Binding Security of
  Implicitly-Rejecting KEMs and Application to BIKE and HQC.* IACR
  Communications in Cryptology, Vol. 2, No. 2 (2025),
  doi:10.62056/ak2i893y6; Cryptology ePrint Archive, Paper 2024/1233.
  [verified online: bibliographic data and abstract; per-notion HQC results
  and the HQC version analysed not verified here]
- [Sch24] S. Schmieg. *Unbindable Kemmy Schmidt: ML-KEM is neither
  MAL-BIND-K-CT nor MAL-BIND-K-PK.* Cryptology ePrint Archive, Paper 2024/523.
  [verified online: title and main result as summarised by the ePrint listing]
- [CDFFJ21] C. Cremers, S. Düzlü, R. Fiedler, M. Fischlin, C. Janson.
  *BUFFing signature schemes beyond unforgeability and the case of
  post-quantum signatures.* IEEE S&P 2021, pp. 1696–1714; Cryptology ePrint
  Archive, Paper 2020/1525 (with a 2023 correction to non re-signability).
  [verified online]
- [DFF24] S. Düzlü, R. Fiedler, M. Fischlin. *BUFFing FALCON without
  Increasing the Signature Size.* SAC 2024, LNCS, pp. 131–150. [verified online]

## Suggestions for the field

These are **suggestions**, not results of cryptanalysis. Each follows from
something this project observed while building and testing VYRA, and each
names that evidence in the repository. They are offered modestly: a single
research project's experience, not a survey.

1. **KEM known-answer sets should include invalid ciphertexts.** The official
   HQC v5.1 KAT files exercise key generation, encapsulation and honest
   decapsulation only (`crates/vyra-hqc/tests/data/PROVENANCE.md`: the
   generator checks that decapsulation returns the same `ss`). The
   implicit-rejection key — the part of an FO-transformed KEM that only
   malformed inputs reach — therefore has no external known answers, and a
   port such as `vyra-hqc` can be checked on it only against itself.
2. **Reference repositories should tag every commit from which published KAT
   files are generated, and implementations should state that tag.** The
   upstream crate VYRA first used cited a reference commit (`161cd4f`) that is
   not in the official repository's history; its KAT files match the blob ids
   of a different, untagged commit (`crates/vyra-hqc/NOTICE.md`; D-11 history,
   RULES 4).
3. **Hybrid and composite specifications should require canonical,
   subgroup-checked public keys before hashing them into a binding.** A
   widely used Ed25519 library, `ed25519-dalek` 3.0, decodes 26 of 40
   enumerated non-canonical encodings and accepts all 7 constructed canonical
   mixed-order keys without flagging them weak (`pk_validation.rs`:
   `ed25519_non_canonical_enumeration`, `canonical_mixed_order_keys_rejected`,
   `standalone_adapter_rejects_mixed_order_keys_that_dalek_accepts`). A
   composite that hashes raw key bytes inherits these ambiguities unless it
   validates first (RULES 12, 18).
4. **Composites should context-bind every component, using a context-bearing
   variant where the default mode has none.** In VYRA's own experiment, a
   transition composite whose Ed25519 half was PureEd25519 was forgeable
   (200/200) once ML-DSA was modelled as forgeable, by an adversary with only
   a standalone Ed25519 signing oracle on the same key; with Ed25519ph under
   the composite context the attack found nothing (STRIP-STANDALONE,
   `VyraPureEd` vs `Vyra`, `results/yield-matrix.md`; D-17; RULES 28). Where
   the only available context variant prehashes, the added collision
   assumption should be stated (RULES 29).
5. **Seed-form keys need explicit suite binding.** Storing secret keys as seeds
   (which removes malformed-expanded-key attacks and stored public data) makes
   them length-uniform across parameter sets, so length no longer separates
   suites; VYRA needed a suite-bound check value after relabelled keys parsed
   (D-12, D-13, §5.2 of `docs/SPEC.md`; RULES 6, 14).
6. **Combiner and composite specifications should be accompanied by a published
   failure-injection matrix** — deliberately broken components plugged into
   the real composition code, explicit games, and named insecure baselines
   (such as `KDF(k1 ‖ k2)` and XOR) as controls that must break. In this
   project the matrix reproduced the known D-01 counterexample, exposed one
   real design weakness (item 4) before publication, and documents which
   properties a design does not have (SUF-CMA with one malleable component).
   It complements proofs; it is not one (`crates/vyra-yield`; D-16).
7. **Component interfaces should expose "derive the public key from the
   secret key".** Compositions that hash public keys into a binding then never
   need to store redundant public data, which can disagree with the secret
   (VYRA's earlier HQC secret key embedded a public key that decapsulation used
   but never checked: D-13; SLH-DSA's `PK.root` is recomputed for the same
   reason; RULES 7).
