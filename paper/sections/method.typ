#import "common.typ": *

= Method: failure injection for yielding resistance <sec-method>

The experiment (`crates/vyra-yield`; decisions D-16, D-17) turns "the composition survives one
component yielding" into a falsifiable statement. It replaces components of a real composition by
deliberately broken models, plays explicit security games with concrete adversaries, and compares
VYRA's design with alternative designs in the same harness. Its outputs are
`results/yield-matrix.json` and `.md`. @fig-method shows the pipeline and the controls.

// Source: paper/figures/method.svg, drawn by tools/figures/gen_figures.py from results/.
#figure(
  placement: top,
  scope: "parent",
  caption: [The failure-injection pipeline and what keeps it honest. Counts are computed from `results/yield-matrix.json`. NO ATTACK FOUND means only that the implemented adversaries did not win against an idealised failure.],
  image("../figures/method.svg", width: 100%),
) <fig-method>

== Principle and scope

A *cell* fixes a primitive and component pair, a design, a failure model for each component (a
_pattern_), a game and an adversary; it runs $N$ seeded trials and records the number of wins. The
KEM experiment uses ML-KEM-512 and HQC-128 through VYRA's adapters (the components of
VYRA-KEM-1). The signature experiment uses two pairs: ML-DSA-44 + Ed25519 (VYRA-SIG-2, the
_transition_ pair) and ML-DSA-44 + SLH-DSA-SHAKE-128s (VYRA-SIG-PQ1, the _dual-PQ_ pair, real
SLH-DSA, no stand-in). VYRA's own designs run through `CustomHybridKem` and `CustomComposite`, which
are byte-equal to the named suites (@sec-arch). Each pattern is either both components real, exactly
one failed, or both failed.

== Failure models

Every model wraps the _real_ component and breaks exactly one property on purpose; a test checks
that each model keeps correctness and breaks what it claims to (#tname("models_break_what_they_say"), #tname("models_keep_correctness_and_break_what_they_say")). @tab-models lists them. The models are
idealised: they describe a property that is lost, not how a real break would happen.

// Source: results/yield-matrix.md, "Failure models" (KEM and signatures); crates/vyra-yield/src/models.
#figure(
  caption: [Failure models (intentionally insecure). Each wraps the real component.],
  tsmall(table(
    columns: (auto, 1fr),
    align: left,
    table.hline(stroke: 0.6pt),
    table.header([*Model*], [*What is broken, and how*]),
    table.hline(stroke: 0.4pt),
    table.cell(colspan: 2, emph[KEM components]),
    [Leaky (Lk)], [confidentiality: the key is a public hash of the label, public key and ciphertext],
    [Malleable (Ml)], [non-malleability: decapsulation ignores one extra ciphertext byte],
    [KeySubst. (KS)], [MAL-BIND-K-PK: public keys carry a tag that decapsulation ignores],
    [Constant (Cn)], [everything: the key is a fixed public constant],
    [SenderKeyed (SK)], [HON-BIND: the encapsulator chooses the key and can re-encapsulate it],
    table.hline(stroke: 0.3pt),
    table.cell(colspan: 2, emph[Signature components]),
    [Forgeable (Fg)], [EUF-CMA: a public tag $"XOF"("label", "pk", "ctx", m)$ always verifies],
    [Malleable (Ml)], [SUF-CMA: verification ignores one extra signature byte],
    [KeySubst. (KS)], [exclusive ownership: public keys carry a 16-byte tag that verification ignores],
    [ContextIgn. (CI)], [context binding: the half is the default standalone signature (empty-context ML-DSA/SLH-DSA, PureEd25519)],
    [MessageColl. (MC)], [message binding: the component signs a 12-bit digest of the message],
    table.hline(stroke: 0.6pt),
  )),
) <tab-models>

== Designs compared

*KEM combiners.* `Naive` $= "SHA3-256"(k_1 || k_2)$; `Xor` $= k_1 xor k_2$; `CtBound`
$= H(k_1, k_2, c_1, c_2)$ (ciphertexts only); `XWingStyle` $= H(k_1, k_2, c_2, "pk"_2)$, which
hashes only component 2's ciphertext and public key (here HQC's) and is _in the style of_ X-Wing,
not X-Wing; and `Vyra`, the real `vyra_kem::combine`. `Naive` and `Xor` are the *named insecure
baselines*: theory predicts their breaks, so they must break.

*Signature compositions.* `Vyra` (both halves sign $M'$ under the composite context; AND);
`VyraPureEd` (as `Vyra`, but the Ed25519 half is PureEd25519 over $M'$, i.e. VYRA's earlier
design, kept as a regression control); `Concat` (both sign $M$ in default mode; AND); `ConcatCtx`
(both sign a context-framed message in default mode, without public-key binding; AND); and
`Either` (VYRA's representative and contexts, but OR-verification). The dual-PQ pair runs only
`Vyra` and `Concat`.

== Games

@tab-games lists the games, their sources and which definitions are ours. A message is a pair
$(M, "ctx")$.

// Source: results/yield-matrix.md, "Games" (KEM and signatures); docs/SECURITY.md.
#figure(
  caption: [Games. "Ours" marks definitions made for this experiment.],
  tsmall(table(
    columns: (20mm, 1fr, 12mm),
    align: (left, left, left),
    table.hline(stroke: 0.6pt),
    table.header([*Game*], [*Win condition*], [*Source*]),
    table.hline(stroke: 0.4pt),
    [IND-CCA2], [real-or-random key; the decapsulation oracle refuses only the challenge ciphertext], [standard],
    [X-BIND-K-CT, \ X-BIND-K-PK], [two decapsulations (no error) give equal keys while the ciphertexts (resp. public keys) differ. X = HON: honest keys, oracles; LEAK: honest keys, secret keys leaked; MAL: adversary-chosen secret keys, scenario I (Decaps--Decaps) only], [#cite-n("CDM23") as restated in #cite-n("KSW25")],
    [EUF-CMA, \ SUF-CMA], [standard (fresh message; fresh message--signature pair)], [#cite-n("DFF24")],
    [S-CEO, MBS], [an oracle signature verifies the same message under $"pk"' != "pk"$; one signature verifies two messages under an adversary key], [#cite-n("CDFFJ21") via #cite-n("DFF24")],
    [STRIP-\ COMPOSITE], [a half of an oracle composite signature is accepted by a standalone verifier of that component (default mode; context mode with empty or foreign context)], [ours],
    [STRIP-\ STANDALONE], [no composite oracle; standalone signing oracles on _both_ component keys in four modes (default; context mode with empty context; foreign context; another VYRA suite's context); any valid composite wins. The composite's _own_ context is refused by definition], [ours],
    [MIX], [halves of two honest signers verify under a mixed key $"pk"_(A,1) || "pk"_(B,2)$], [ours],
    [CROSS-SUITE, \ CROSS-CONTEXT], [a signature for suite byte (context) A verifies for B], [ours],
    table.hline(stroke: 0.6pt),
  )),
) <tab-games>

== Adversaries

Adversaries are concrete strategies, eleven for the KEM and fifteen for signatures. KEM:
`CoinFlip` (trivial), `MaulReplay-1/2` (maul one side of the challenge, query the oracle, compare),
`MixAndMatch` (query mixed ciphertexts and XOR-combine), `Recompute` (predict both component keys
from the models), `SecondCiphertext-1/2/12` and `CrossKey-1/2/12` (binding). Signatures: `Garbage`
(trivial), `Forge`, `Collide`, `Maul`, `StripHalf-1/2`, four `Recombine-*` (one per standalone
oracle mode), `SubstituteKey`, `Collapse`, `MixHalves`, `Relabel`, `SwapContext`. Binding and
separation adversaries try every subset of components, not only the broken ones (RULES 26).
Adversaries are game-specific: a cell reports only the strategies implemented for its game.

== Statistics and verdict rule

Each trial is seeded from the cell's label under the master seed `VYRA-YIELD-U11`. For $w$ wins in
$n$ trials the harness computes the one-sided exact binomial p-value $Pr["Bin"(n, p_0) >= w]$ of
$H_0: p <= p_0$, with $p_0 = 1\/2$ for IND-CCA2 (advantage $2 hat(p) - 1$) and $p_0 = 2^(-128)$ for
all search games (advantage $hat(p)$). A cell is *BROKEN* iff the p-value is below $10^(-6)$;
otherwise it is *NO ATTACK FOUND*. No other verdict exists, and none says "secure". Intervals are 99%
Wilson intervals. A Bonferroni bound over all 3365 cells keeps the chance of any false BROKEN below
$3.4 dot 10^(-3)$. The rule has three consequences that matter for reading the results. At
$n = 200$, a BROKEN verdict in IND-CCA2 needs at least 134 wins (advantage at least 0.34). In
search games, a single challenger-verified win is BROKEN. And zero wins bound the success probability
only weakly: the 99% upper limit is 0.032 at $n = 200$ and 0.356 at $n = 12$. Trials per cell are 200
for the KEM and the transition pair, and 12 for the dual-PQ pair, whose SLH-DSA signing takes
seconds per signature.

== Controls

Controls show that the harness can produce each verdict where theory dictates it.

- *Positive.* Both KEM components confidentiality-broken (Leaky or Constant) $=>$ every combiner
  BROKEN in IND-CCA2 (control A, 15 cells); `Naive` over Constant $times$ Constant $=>$ BROKEN in
  every binding game (A2); both signature components Forgeable $=>$ `Forge` wins EUF-CMA against
  every composition (S-A).
- *Named insecure baselines.* `Naive` with one Malleable component is BROKEN in IND-CCA2 by mauling
  that side (control C, the D-01 counterexample); `Xor` over two _real_ components is BROKEN by
  `MixAndMatch` and by nothing else (B-XOR, 23 cells); `Either` with one Forgeable component is
  BROKEN in EUF-CMA (S-C). A baseline insecure even with sound components is named and asserted,
  not excluded (RULES 25).
- *Negative.* Both components real $=>$ no adversary wins against `Naive`, `CtBound`, `XWingStyle`
  and `Vyra` (B, 92 cells); for signatures the by-design weaknesses of the comparison designs are
  named per cell (S-B, 101 cells); the trivial adversaries never win (D, 85 cells; S-D, 80 cells).
- *Calibration.* `CoinFlip` against `Vyra` over two real KEMs, 2000 trials: 1023 wins, NO ATTACK
  FOUND. `Garbage` against the transition `Vyra` in EUF-CMA, 2000 trials: 0 wins.
- *Regression (before/after).* `VyraPureEd` with Forgeable ML-DSA must stay BROKEN in
  STRIP-STANDALONE (S-E). The control keeps the finding of @sec-sig-results reproducible after the
  fix and shows that the harness still detects it.

== Expectation rule

Every cell carries `expected` (BROKEN, NO ATTACK FOUND or UNSPECIFIED) and `expected_basis`, which
must name a claim (e.g. `claim:V1`: VYRA's combiner with exactly one failed component), a control or a
theory, and must follow the project's documented claim, never the observed result (RULES 35). Gate
Y2 fails if any cell with a stated expectation shows the other verdict. In the committed matrix no
cell contradicts its expectation. Of 3365 cells, 759 carry an expectation and 2606 are UNSPECIFIED;
the verdicts of the latter are observations, not tests of a pre-stated prediction.

== Determinism

The matrix is deterministic: all randomness derives from cell labels, execution is a deterministic
parallel map, and gate Y2 regenerates the JSON and requires it to be byte-identical to the committed
file. Two consecutive runs of the final version were recorded as identical (`docs/ATTEMPTS.md`,
U11-S-R1). A full run takes about two minutes in release mode on a many-core machine.
