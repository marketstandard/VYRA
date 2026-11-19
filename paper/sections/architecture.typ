#import "common.typ": *
#import "../data/sizes.typ": *

= Architecture <sec-arch>

This section describes VYRA wire version 1 as specified in `docs/SPEC.md` and implemented in the
crates at version 0.1.0. Only the encodings are ours; every technique is established
(`docs/SPEC.md` labels each part ESTABLISHED or VYRA-ORIGINAL). @fig-construction gives an overview
of the two constructions.

// Source: paper/figures/construction.svg, drawn by tools/figures/gen_figures.py from results/.
#figure(
  placement: top,
  scope: "parent",
  caption: [The two constructions. (a) Hybrid KEM: one SHA3-256 hash over a length-framed transcript binds both component keys, both ciphertexts, both public keys and the suite. (b) Composite signature: both halves sign the message representative $M'$, each under a VYRA-specific context, and both must verify. Details: @sec-arch-kem and @sec-arch-sig.],
  image("../figures/construction.svg", width: 100%),
) <fig-construction>

== Replaceable components

Components implement small traits from `vyra-core` and `vyra-sig`: `Kem` and `ComponentKem` for
key encapsulation, `SignatureScheme` and `CompositeComponent` for signatures. The hybrid KEM and the
composite signature hold their components as trait objects, and the suite-to-component mapping is
defined in exactly one function per primitive (RULES 13). Two public entry points,
`CustomHybridKem` and `CustomComposite`, run the _same_ composition code over caller-supplied
components and a caller-chosen descriptor; they have no wire format and VYRA makes no security
statement about them. Tests rebuild each named suite from its components through these entry points
and require byte-equal outputs (gate S6 and three tests in `vyra-yield`, e.g.
#tname("vyra_assembly_equals_named_dual_pq_suite")). This is
what makes the experiment of @sec-method possible: a broken component model is just another
implementation of the trait, and the composition code under test is the shipped code, not a copy
(RULES 27).

All VYRA crates forbid `unsafe` (gate S7), and library code compiles with Clippy's `unwrap_used`,
`expect_used`, `panic` and `indexing_slicing` denied (gate S8), except seven forked arithmetic
modules of the HQC port (@sec-conf). Secret types zeroise on drop, redact under `Debug` and compare
in constant time through `subtle`; this is best effort (gate S9, inspection).

== Transcript framing and wire format

VYRA's own hashing goes through one transcript function. With $"frame"(x) = "u64_be"(|x|) || x$,
$
  F &= "frame"(ell) || "frame"(f_1) || ... || "frame"(f_n), \
  T(ell; f_1, ..., f_n) &= "SHA3-256"(F), \
  T_"xof" (ell; f_1, ..., f_n; L) &= "SHAKE256"(mono("0x01") || F)[0..L].
$
Distinct labels separate the uses (combiner, public-key digest, two secret-key check values,
sealed-box KDF). Injectivity of $F$ is the property that the bounded model checking of
@sec-bmc addresses. Every serialised object is a 7-byte header (magic `VYRA`, version 1, object type,
suite identifier) followed by a payload of fixed length per suite; decoders reject every other
length, header or suite and never panic (gates S1, S2, S10).

== Hybrid KEM <sec-arch-kem>

The suites VYRA-KEM-1, VYRA-KEM-3 and VYRA-KEM-5 pair ML-KEM-512, ML-KEM-768 and ML-KEM-1024 with HQC-128, HQC-192 and HQC-256 (HQC-1, HQC-3 and HQC-5 of v5.1). Secret keys
are the components' key-generation seeds: ML-KEM's 64-byte $d || z$ and HQC's 32-byte
`seed_kem`, which in v5.1 is exactly the specification's compressed decapsulation key. Public keys
used in the combiner are re-derived from the seeds at decapsulation, so a stored secret key cannot
carry public data that contradicts it (RULES 7). Because a 96-byte seed string is a valid secret key
for every suite, the wire form appends a 16-byte check value $T("VYRA-KEM-SK-v1"; [s], "sk")[0..16]$,
recomputed and compared in constant time on parse; it detects relabelling and corruption and is not
a MAC (RULES 6, 15). Public keys are validated on parse and before every encapsulation: the FIPS 203
modulus check for ML-KEM, and zero padding bits above position $n - 1$ in the last HQC byte, a
strictness addition that gives each HQC public key one encoding. Decapsulation runs both components
before inspecting either, rejects implicitly like both components, and errors only on malformed
input (D-02).

#algo(placement: top)[VYRA-KEM (`vyra-kem`: `hybrid.rs`, `combiner.rs`). $E(n)$ draws $n$
  bytes; $k = 16, 24, 32$ for suites 1, 3, 5.][
```text
KeyGen(s):
  d‖z ← E(64);  pk1 ← ML-KEM.KeyGen_internal(d, z).ek
  seed ← E(32); pk2 ← HQC.KeyGen(seed).ek
  return (pk1‖pk2, d‖z‖seed)             # sk: 96 B
Encaps(s, pk):
  require |pk| = pk_len(s)
  require ModulusOk(pk1), PaddingZero(pk2)
  (ct1, ss1) ← ML-KEM.Encaps(pk1)        # E(32)
  (ct2, ss2) ← HQC.Encaps(pk2)           # E(k+16)
  K ← Combine(s, ss1, ss2, ct1, ct2, pk1, pk2)
  return (ct1‖ct2, K)
Decaps(s, d‖z‖seed, ct1‖ct2):   # lengths checked
  (pk1, dk1) ← ML-KEM.KeyGen_internal(d, z)
  (pk2, dk2) ← HQC.KeyGen(seed)
  ss1 ← ML-KEM.Decaps(dk1, ct1)          # impl. rej.
  ss2 ← HQC.Decaps(dk2, ct2)             # impl. rej.
  return Combine(s, ss1, ss2, ct1, ct2, pk1, pk2)
Combine(s, ss1, ss2, ct1, ct2, pk1, pk2) :=
  T("VYRA-KEM-v1"; [s], ss1, ss2, ct1, ct2, pk1, pk2)
```
] <alg-kem>

The combiner (@alg-kem) hashes the label, the suite, both shared secrets, both ciphertexts and both
public keys. Hashing the ciphertexts is the GHP18 construction; hashing the public keys aims at
binding of the key to the public keys independently of the components' own binding properties, an
informal argument only (`docs/SECURITY.md`, combiner gap 6). The price is hashing 8--25 KB per
operation, which needs no component-specific property, unlike X-Wing's omission of the ML-KEM
ciphertext.

== Composite signatures <sec-arch-sig>

*Two families, one engine.* The transition suites VYRA-SIG-2, VYRA-SIG-3 and VYRA-SIG-5 pair ML-DSA-44, ML-DSA-65 and ML-DSA-87 with Ed25519;
the suite label is the ML-DSA category only, since Ed25519 offers roughly 128-bit classical security
and none against a quantum adversary. The dual post-quantum suites VYRA-SIG-PQ1, VYRA-SIG-PQ3 and VYRA-SIG-PQ5 pair
the same ML-DSA sets with SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192s and SLH-DSA-SHAKE-256s, labelled with the minimum of the two claimed
categories.

*Message representative.* Both components sign
$M' = mono("\"VYRA-SIG-v1\"") || [s] || "pk_digest" || [|"ctx"|] || "ctx" || M$, where
$"pk_digest" = T("VYRA-SIG-PK-v1"; [s], "pk"_1, "pk"_2)$ binds the whole composite public key
(RULES 8), $|"ctx"| <= 255$, and $M$ is not pre-hashed. The layout function is injective for fixed
suite and digest; @sec-bmc checks this for short contexts and messages.

*Every half is context-bound.* Each component signs $M'$ under the composite context
$c_s = mono("\"VYRA-SIG-v1\"") || [s]$ through a context-bearing mode: ML-DSA and SLH-DSA through
their FIPS 204/205 context input, Ed25519 as RFC 8032 Ed25519ph with context $c_s$. Ed25519ph's
domain prefix makes its signatures invalid as PureEd25519 signatures, so no half of a named suite
is a valid default-mode standalone signature (tested in `separation.rs`). We use Ed25519ph rather
than Ed25519ctx because `ed25519-dalek` 3.0 exposes no Ed25519ctx interface. The cost is an
assumption delta: the Ed25519 half signs $"SHA-512"(M')$, so a SHA-512 collision between two
representatives forges _that half_; the ML-DSA half still signs $M'$ unhashed (D-17, RULES 29). The
design was PureEd25519 until the experiment of @sec-results showed why it should not be.

*Keys and validation.* Secret keys are seeds: ML-DSA's 32-byte $xi$; the Ed25519 private key;
for SLH-DSA, `SK.seed ‖ SK.prf ‖ PK.seed` (3n bytes), with `PK.root` recomputed on every signing
call so that no stored copy can disagree with the seeds. Wire secret keys carry a check value as for
the KEM. Composite public keys are validated on parse and inside every verification: the Ed25519 part
must decompress, be canonically encoded, not be of small order and lie in the prime-order subgroup
(RULES 12, 18); ML-DSA and SLH-DSA parts need only a length check because every string of the right
length is a canonical key.

#algo(placement: top)[VYRA-SIG (`vyra-sig`: `composite.rs`, `message.rs`). Half 2 is Ed25519ph
  (transition) or SLH-DSA (dual post-quantum).][
```text
c_s := "VYRA-SIG-v1"‖[s]             # 12 B, every half
Rep(s, pk, ctx, M) :=                # |ctx| ≤ 255
  "VYRA-SIG-v1"‖[s]‖T("VYRA-SIG-PK-v1"; [s], pk1, pk2)
  ‖[|ctx|]‖ctx‖M
Sign(s, sk1‖sk2, M, ctx):
  pk ← re-derived from sk1, sk2
  M' ← Rep(s, pk, ctx, M)
  σ1 ← ML-DSA.Sign(sk1, M', c_s)       # hedged, E(32)
  σ2 ← Ed25519ph.Sign(sk2, SHA-512(M'), c_s)  # det.
     | SLH-DSA.Sign(sk2, M', c_s)      # hedged, E(n)
  return σ1‖σ2
Verify(s, pk, M, ctx, σ1‖σ2):        # exact lengths
  M' ← Rep(s, pk, ctx, M)
  a ← ValidatePk(s, pk)  # canonical, prime order
  b ← ML-DSA.Verify(pk1, M', σ1, c_s)
  c ← Half2.Verify(pk2, M', σ2, c_s)
  return (a & b & c) ? Ok : VerificationFailed
```
] <alg-sig>

== Sealed box

The sealed box is KEM-DEM: a fresh VYRA-KEM encapsulation $(c_"kem", K)$ per message, a key and
nonce
$ "key" || "nonce" = T_"xof" ("VYRA-SEAL-v1"; [s], K, c_"kem"; 44), $
and ChaCha20-Poly1305 with associated data $mono("\"VYRA-SEAL-v1\"") || [s] || "aad"$. It provides no sender authentication
and no forward secrecy with a static recipient key (D-03), and it is single-shot. It is not part
of the experiment.

== Object sizes

@tab-comp and @tab-suites list all sizes, generated by `cargo xtask sizes` from code constants, each
asserted equal to the length of a generated object.

// Source: results/sizes.json ("components"), via paper/data/sizes.typ (generated).
#figure(
  caption: [Component encodings as stored by VYRA (bytes). Secret keys are seeds. Cat.: the NIST
    category claimed by the component's specification (for Ed25519 a classical-strength label only).],
  tsmall(table(
    columns: (auto, auto, auto, auto, auto, auto),
    align: (left, center, right, right, right, right),
    table.hline(stroke: 0.6pt),
    table.header([*Component*], [*Cat.*], [*pk*], [*sk*], [*ct / sig*], [*ss*]),
    table.hline(stroke: 0.4pt),
    ..size-components.map(c => (c.at(0), str(c.at(2)), str(c.at(3)), str(c.at(4)),
      str(c.at(5)), c.at(6))).flatten(),
    table.hline(stroke: 0.6pt),
  )),
) <tab-comp>

// Source: results/sizes.json ("kem_suites", "sig_suites", "seal_suites"), via
// paper/data/sizes.typ (generated). Wire = raw + 7-byte header (+ 16-byte check value for sk).
#figure(
  caption: [The nine suites (bytes), raw / wire. Wire = 7-byte header + raw; wire secret keys
    also carry the 16-byte check value. Sealed-box overhead (header + KEM ciphertext + tag) for
    VYRA-KEM-1/3/5: #size-seal.map(r => str(r.at(4))).join(" / ") bytes. Components: @sec-arch-kem and @sec-arch-sig.],
  tsmall(table(
    columns: (auto, auto, auto, auto, auto, auto),
    align: (left, right, center, right, right, right),
    table.hline(stroke: 0.6pt),
    table.header([*Suite*], [*id*], [*Cat.*], [*pk*], [*sk*], [*ct / sig*]),
    table.hline(stroke: 0.4pt),
    ..size-kem.map(k => (k.at(0), str(k.at(1)), str(k.at(3)),
      [#k.at(4) / #k.at(5)], [#k.at(6) / #k.at(7)], [#k.at(8) / #k.at(9)])).flatten(),
    table.hline(stroke: 0.3pt),
    ..size-sig.map(k => (k.at(0), str(k.at(2)), str(k.at(4)),
      [#k.at(5) / #k.at(6)], [#k.at(7) / #k.at(8)], [#k.at(9) / #k.at(10)])).flatten(),
    table.hline(stroke: 0.6pt),
  )),
) <tab-suites>

One length coincidence exists across families: VYRA-SIG-2 and VYRA-SIG-PQ1 public keys are both
1344 bytes raw. A relabelled key parses but fails closed, because the suite is in $M'$, in the
context and in the public-key digest, and the signature lengths differ (`docs/SPEC.md` §7.7;
RULES 31).
