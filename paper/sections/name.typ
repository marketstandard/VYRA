#import "common.typ": *

= What the name claims <sec-name>

A name made of adjectives invites overreading, so each word is defined by the evidence behind it
(`docs/SECURITY.md` §What the name means; decision D-15). @tab-name is the definition this paper
uses throughout.

// Source: docs/SECURITY.md "What the name means" and docs/DECISIONS.md D-15.
#figure(
  placement: top,
  scope: "parent",
  caption: [The name, word by word: meaning, evidence class and explicit non-claims.],
  tsmall(table(
    columns: (auto, 2.1fr, 1.1fr, 1.5fr),
    align: left,
    table.hline(stroke: 0.6pt),
    table.header([*Word*], [*Meaning in VYRA*], [*Evidence*], [*Not claimed*]),
    table.hline(stroke: 0.4pt),
    [Yielding Resistance],
    [The security goals are designed to survive one component family yielding: ML-KEM or HQC for
      key establishment; ML-DSA or SLH-DSA in the dual post-quantum signature suites. The
      transition suites (ML-DSA + Ed25519) give no second line against a quantum adversary.],
    [cited theorem for the combiner technique; unreviewed proof sketches; failure injection
      (@sec-method, @sec-results)],
    [a proof for VYRA's instantiation; anything about real cryptanalytic breaks, which need not
      resemble the failure models; a QROM result],
    table.hline(stroke: 0.3pt),
    [Verified],
    [Claims about _behaviour_ are tied to reproducible machine checks: official vectors for the
      components, failure-injection games for the compositions, exhaustive enumeration and bounded
      model checking for VYRA's encodings, pre-registered gates.],
    [tests, failure injection, enumeration, bounded model checking],
    [formal verification of the cryptography; verified constant-time behaviour; review or
      validation by anyone outside the project; certification],
    table.hline(stroke: 0.3pt),
    [Architecture],
    [Components sit behind small traits and can be replaced; the same composition code runs named
      suites and custom assemblies.],
    [byte-equality tests; inspection],
    [that an arbitrary custom assembly is secure],
    table.hline(stroke: 0.6pt),
  )),
) <tab-name>

*Does VYRA live up to its name?* In the following senses, yes. For the KEM, the combiner
technique has a published theorem #cite-n("GHP18"), and in our experiment no implemented
adversary won in any of the 230 cells where exactly one component was replaced by a broken model,
while baselines in the same harness fell. For signatures, the dual post-quantum suites pair two
unrelated post-quantum assumptions, and no implemented adversary forged a VYRA composite with one
forgeable component. Every claim about behaviour points to a check that anyone can rerun
(@sec-repro).

In the following senses, not yet. (i) No proof covers VYRA's concrete encodings; the sketches are
our own and unreviewed. (ii) The failure models are idealised: a real break of ML-KEM or HQC will
not look like "an ignored ciphertext byte". (iii) The composite signature does _not_ yield-resist
for strong unforgeability: one malleable or forgeable component lets an adversary produce a new
signature on an old message, which the experiment shows directly. (iv) Separation of the
signature halves holds only for components that honour the context; a context-ignoring component
breaks it. (v) The dual post-quantum evidence rests on 12 trials per cell. (vi) The transition
suites offer no yielding resistance against a quantum adversary at all. (vii) "Verified" does not
extend to timing, zeroisation or the components' internals. The name is therefore a statement of
design goals with stated evidence, not a guarantee.
