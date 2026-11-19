#import "common.typ": *

= Limitations <sec-limits>

The full list is in `docs/SECURITY.md` §Limitations; the most important items are these.

- *No proof and no external review.* No security proof exists for VYRA's instantiation of the
  combiner, the composites or the sealed box; the sketches are ours and unreviewed. Nobody outside
  the project has analysed, audited or tested VYRA.
- *Failure injection is not a proof* and has the limits of @sec-threats.
- *Machine checks cover only VYRA's own encodings within stated bounds*; framing injectivity beyond
  the bounds rests on a hand argument from the all-lengths prefix lemma.
- *HQC is VYRA-maintained code* for a scheme that is not yet a standard, conformant only to the
  designers' honest-path vectors, with no independent v5.1 implementation to compare against. The
  hybrid exists to survive a break of ML-KEM, and in that case everything rests on this port.
- *Constant-time behaviour is unverified*: VYRA's glue by inspection only; the HQC port by structure,
  a CPU-multiplier assumption and one smoke test; upstream crates unmeasured. FO re-encryption can
  act as a plaintext-checking oracle under power or EM leakage #cite-n("RRCB20", "UXTITH22")\; VYRA
  has no countermeasure and claims no physical-attack resistance. Seed-only keys run full key
  generation on every private operation, which multiplies secret-dependent computation.
- *Transition suites* give no second line against a quantum adversary, and add a SHA-512 collision
  assumption for the Ed25519ph half. *The composites are not SUF-CMA* with one malleable component.
- *Component keys must not be used outside the composite*: an oracle that signs under the
  composite's own context produces composite halves.
- *Security categories* are the component designers' claims; no estimator was run. VYRA is not
  interoperable with any standardised hybrid or composite, and not validated or certified.

= Reproducibility <sec-repro>

The repository (Rust edition 2024; minimum Rust 1.88, on which the whole workspace test suite
passes (426 tests, `docs/ATTEMPTS.md`); benchmarks on Rust 1.98; licence MIT OR Apache-2.0)
reproduces every number in this paper with these commands from the repository root.

#block(inset: (left: 0.5em))[
  #set text(size: 7.4pt)
  #set par(justify: false)
  - `cargo xtask verify` --- every pre-registered gate (`docs/CHECKS.md`); writes
    `results/verification-report.*`.
  - `cargo run -p vyra-yield --release --bin yield-report -- --out results/` --- the failure-injection
    matrix (deterministic; about 2 minutes in release on a many-core machine).
  - `tools/kani/run.ps1` or `tools/kani/run.sh` --- bounded model checking in a pinned Docker image
    (1079 s end to end in the recorded run).
  - `cargo xtask vectors --check` --- VYRA's own known-answer vectors (about 40 s).
  - `cargo xtask bench` --- benchmarks (several minutes); `cargo xtask sizes` --- sizes.
  - `typst compile paper/vyra.typ paper/vyra.pdf` --- this paper (Typst 0.15.1, built-in fonts, no
    packages); `python paper/tools/gen_data.py` regenerates its data files from `results/`, and
    `python paper/tools/check_numbers.py` cross-checks every quoted number.
]

*How the work was done.* The pass conditions (`docs/CHECKS.md`: gate families F functional, S
implementation security, C claims discipline, P performance, D documentation, X scope) were written
before any code; families Y (yielding resistance) and V (machine-checked properties) were added
with the experiment and the proofs. Work was split into units;
each unit had fixed check commands and at most three attempts, and every attempt, including
failures, was logged with its evidence (`docs/ATTEMPTS.md`). At the time of writing, the first 61
rows of that log record 42 PASS and 15 FAIL verdicts (the latter including the internal review R1,
logged as FAIL with its findings, and one attempt stopped by the implementer for a design
decision), one PARTIAL, and 3 rows that replace or clarify a check; no unit failed all three
attempts, and three passed only at the third. The review R1 read the code after the first round;
it was internal to the project and is not an external audit. A lesson entered `RULES.md` only
after its fix passed. `cargo xtask verify` runs all 37 gates, including Y and V, and writes
`results/verification-report.md`; that file records the run on the commit that carries this
paper, and we quote no pass count here because the report is produced after the paper is built.

*Origin of this work.* VYRA began from an informal design note that proposed a hybrid KEM with key
$"KDF"(k_1 || k_2)$; that combiner is the `Naive` baseline of our experiment. Nothing else in this
paper depends on the note.

= Conclusion <sec-concl>

Yielding resistance is the property hybrids are built for, and it can be tested directly: replace a
component by a broken model, keep the real composition code, play explicit games, and run the same
attacks against named insecure baselines that must break. In VYRA this re-confirmed the known
breaks, showed that VYRA's combiner withstood every implemented attack in every one-failure cell,
documented a property the composite does not have, and found one real defect in our own signature
design before publication. That is modest evidence, strictly weaker than a proof, against idealised
failure models, from a project nobody outside has reviewed. We think the method is worth more than
our instance of it, and the most useful next step is to apply it to the hybrid and composite
designs that are actually being deployed.
