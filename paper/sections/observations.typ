#import "common.typ": *

= Observations from building it <sec-obs>

These are engineering findings made while building and checking VYRA. Each is stated on its own,
with the place in the repository where the evidence lives. Most became one of the 39 rules in
`RULES.md`, each of which was added only after the fix it explains had passed its check.

+ *A widely used Ed25519 decoder accepts non-canonical and mixed-order keys.* `ed25519-dalek` 3.0
  decodes 26 of 40 enumerated non-canonical encodings, and accepts all 7 constructed canonical
  mixed-order keys ($A + T$ with $T$ a torsion point) without flagging them weak; plain
  `verify_strict` accepts real signatures under all 7. VYRA rejects all of them by re-encoding and a
  prime-order subgroup check (`pk_validation.rs`; attempts U3-R2, U3-R4, U3-R5; RULES 12, 18).
+ *A component crate implemented an untagged reference commit, with superseded parameters.* The
  only pure-Rust HQC crate that passed our conformance tests cited a commit absent from the
  official history and matched an untagged commit whose secret weights the designers later raised
  (`vyra-hqc/NOTICE.md`; D-11, D-14; RULES 4, 17).
+ *Equal lengths hide a version change.* HQC v5.0-era and v5.1 objects have identical sizes, and
  implicit rejection turns a version mismatch into silently unrelated keys rather than errors; a
  wire version must say which algorithm version it means (D-14; RULES 20).
+ *Seed-form keys defeat length-based suite separation.* Moving all secret keys to seeds made every
  KEM secret key 96 bytes and every transition signature key 64 bytes, so a relabelled wire key
  parsed under another suite. The implementer stopped rather than weaken two tests; the fix is a
  suite-bound check value, and all 952 single-bit flips of a wire KEM secret key are now rejected
  (attempts U2-R2, U3-R3; RULES 6, 14).
+ *Stored public keys inside secret keys can contradict them.* The internal review found the hybrid
  secret key storing an unchecked public key (the only finding recorded with a severity, MEDIUM),
  and the HQC expanded secret key embeds a public key that decapsulation uses but never checks.
  VYRA now re-derives all public data from seeds, including SLH-DSA's `PK.root` (review R1; D-13;
  RULES 7).
+ *Some pre-registered checks could not pass, and some tests could not fail.* "Every secret-key bit
  flip changes the key" is false for ML-KEM's $z$, which the valid-ciphertext path never reads; "a
  raw key of another suite is rejected" cannot hold for suite-less seeds; a tree-cleanliness gate
  could never pass because the verifier itself rewrote benchmark files first. All three were
  replaced, not dropped, and logged (`docs/ATTEMPTS.md`; RULES 10). Separately, tests that assert
  only a marker trait or iterate an empty collection were found and are now counted as inspection,
  not tests (RULES 11).
+ *Length coincidences cross families.* Adding the dual post-quantum family produced one equal
  public-key length across families (VYRA-SIG-2 and VYRA-SIG-PQ1); it fails closed, but it was
  found only by checking every pair of suites (RULES 31).
+ *Context-bearing variants are not always available.* `ed25519-dalek` 3.0 exposes Ed25519ph but no
  Ed25519ctx, so context-binding the Ed25519 half costs a SHA-512 collision assumption for that half
  (D-17; RULES 29).
+ *KAT reproduction is byte-sensitive in unexpected places.* Reproducing the HQC KAT generator
  needed its DRBG's exact request boundaries, not just its byte stream, and a Windows checkout's
  line-ending conversion silently changes KAT file hashes (`vyra-hqc/tests/data/PROVENANCE.md`;
  RULES 19, 22).

= Suggestions for the field <sec-suggest>

These are *suggestions*, not results of cryptanalysis: one project's experience, each tied to
evidence in this paper.

+ *KEM known-answer sets should include invalid ciphertexts.* The official HQC v5.1 KAT files
  exercise only honest decapsulation, so the implicit-rejection path has no external known answers
  and a port can be checked there only against itself (@sec-conf).
+ *Reference repositories should tag every commit from which published KAT files are generated, and
  implementations should state the tag.* An untagged commit led a crate to ship superseded
  parameters (@sec-conf; RULES 4).
+ *Hybrid and composite specifications should require canonical, subgroup-checked public keys
  before hashing them into a binding.* A composite that hashes raw key bytes inherits the decoder's
  ambiguities (@sec-obs, item 1).
+ *Composites should context-bind every component, using a context-bearing variant where the
  default mode has none.* In our experiment, a PureEd25519 half made the composite forgeable (200 of
  200) once ML-DSA was modelled as broken, given only a standalone Ed25519 signing oracle; where the
  only context variant prehashes, the added collision assumption should be stated (@sec-sig-results).
+ *Seed-form keys need explicit suite binding.* Seeds remove malformed-expanded-key attacks and
  stored public data, but make keys length-uniform across parameter sets (@sec-obs, item 4).
+ *Combiner and composite specifications should be accompanied by a published failure-injection
  matrix* with named insecure baselines that must break. Ours reproduced the known counterexample,
  exposed one real design weakness before publication and documents a property the design does not
  have (SUF-CMA with one malleable component). It complements proofs; it is not one (@sec-results).
+ *Component interfaces should expose "derive the public key from the secret key"*, so that
  compositions that hash public keys never store redundant public data that can disagree with the
  secret (@sec-obs, item 5).
+ *Prove fixed-width length-prefix arithmetic for all lengths, separately from bounded content
  proofs.* A truncating prefix survived every bounded proof and exhaustive test of ours until it
  was (@sec-bmc).
