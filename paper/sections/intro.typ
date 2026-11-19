#import "common.typ": *

= Introduction <sec-intro>

A hybrid key-encapsulation mechanism (KEM) runs two KEMs side by side and derives one key from
both; a composite signature has two components sign the same message. Both are deployed for one
reason: the construction should keep its security goal if _one_ component turns out to be broken,
whether by cryptanalysis of a young post-quantum assumption, by a quantum computer that breaks a
classical one, or by an implementation defect. We call this property *yielding resistance*: the
construction resists although one component yields.

For the KEM combiner the property is backed by theory. Giacon, Heuer and Poettering
#cite-n("GHP18") show that a parallel combiner whose key derivation is a split-key PRF over the
component keys _and ciphertexts_ is IND-CCA secure if one ingredient is; hash-based instantiations
are proven in the random-oracle model, and the hash-based split-key PRF also in the quantum ROM
#cite-n("DFH22"). Implementations, however, are tested in a way that never touches this property.
Known-answer tests (KATs) and differential tests check that each component computes what its
specification says, and round-trip tests check that honest parties agree. None of them runs the
composition with a component that is _broken_, which is the only situation in which yielding
resistance matters. A combiner that drops the ciphertexts from its hash, a composite whose halves
can be used separately, or a binding that hashes a non-canonical key all pass every conformance
test.

This paper reports what we did about that gap in one prototype, VYRA (Verified Yielding Resistance
Architecture), and what we think others should take from it. VYRA provides a hybrid KEM (ML-KEM +
HQC), composite signatures in a transition family (ML-DSA + Ed25519) and a dual post-quantum family
(ML-DSA + SLH-DSA), and a KEM-DEM sealed box. Its central addition is a *failure-injection
experiment*: intentionally broken models of the real components are plugged into the real
composition code, explicit games are played by concrete adversaries, the same harness attacks
named insecure baselines, and controls show that the harness can produce both verdicts.

== Contributions

Each item carries its evidence class and our estimate of its size; @sec-value ranks them.

+ #tag[experimental method] *A failure-injection method for yielding resistance* (@sec-method):
  precisely defined failure models for KEMs and signatures, five KEM combiners and five signature
  compositions evaluated in one harness, games taken from the literature plus four defined here,
  positive, negative and regression controls, an exact binomial verdict rule, and a rule that every
  pre-stated expectation names its basis and follows a claim, never a result. The output is
  deterministic and byte-reproducible. _Size:_ modest. The method is simple; its value is that it
  is executable, reusable and was applied before publication.
+ #tag[empirical observation] *A reproducible matrix of 3365 cells* (@sec-results). It re-confirms
  known breaks in executable form (the concatenation-KDF combiner under ciphertext mauling; XOR
  even over two sound components) and records observations: a ciphertext-only combiner loses
  public-key binding under one key-substitutable component, a combiner in the style of X-Wing depends
  on its unhashed component, and VYRA's combiner shows no successful attack in any one-failure cell.
  _Size:_ small; most entries confirm what theory predicts.
+ #tag[empirical observation] *A weakness found in our own design, and its fix, evidenced before
  and after.* With a standalone-valid Ed25519 half, a modelled ML-DSA break and a standalone Ed25519
  signing oracle forged the composite in 200 of 200 trials; with every half bound to a composite
  context, no implemented attack won. _Size:_ small. The underlying issue (separability under key
  reuse) is known in principle; the contribution is a concrete, reproducible instance and the
  regression control that keeps it fixed.
+ #tag[engineering] *VYRA itself* (@sec-arch): replaceable components behind small traits, custom
  assemblies that run the named suites' code byte for byte, dual post-quantum suites for KEM and
  signatures, and a signature design in which every half is context-bound (Ed25519 through
  Ed25519ph). _Size:_ an engineering artefact, not a new construction.
+ #tag[engineering] *A pure-Rust implementation of HQC v5.1* (@sec-conf), ported from a
  pre-v5.1 crate, without `unsafe` and without secret-indexed tables, reproducing all 100 official
  KAT counts of each parameter set. _Size:_ useful to Rust users until an audited crate exists;
  scientifically minor.
+ #tag[tooling] *Bounded model checking of VYRA's own encodings with mutation testing*
  (@sec-bmc), including one methodological lesson: a length-prefix truncation survived every bounded
  content proof and exhaustive test until the prefix arithmetic was proven for all lengths.
  _Size:_ small.
+ #tag[suggestions] *Eight suggestions for the field* (@sec-suggest), each tied to evidence in
  this paper.

== What this paper does not contribute

- *No new primitive and no new combiner technique.* VYRA's KEM combiner, which hashes both shared
  secrets, both ciphertexts, both public keys and the suite, is a parallel combiner in the sense of
  GHP18 #cite-n("GHP18") with the shape the CFRG draft calls the UniversalCombiner
  #cite-n("CFRG-HKEM")\; only the concrete encoding is ours.
- *No security proof for VYRA's instantiation.* The project's own reduction sketches
  (`docs/SECURITY.md`) are unreviewed and list their gaps. Failure injection is falsification
  evidence and strictly weaker than a proof.
- *No external review, audit or cryptanalysis*, and *no constant-time verification*; one coarse
  timing smoke test of the HQC port is the only measurement.
- *No interoperability* with X-Wing #cite-n("XWING"), the CFRG hybrid KEMs or RFC 10073
  composites #cite-n("RFC10073"), and no attempt to test those designs themselves; our
  "X-Wing-style" baseline is a toy in their style.
