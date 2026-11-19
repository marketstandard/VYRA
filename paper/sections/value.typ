#import "common.typ": *

= How much value is this? <sec-value>

We were asked to be frank about this, and we try to be.

*Ranked by likely usefulness to others.*
+ *The method and harness* (@sec-method). A failure-injection matrix with named insecure baselines
  and controls is cheap to build next to any hybrid or composite and catches composition errors that
  conformance tests cannot. It found a real defect in our own design. This is the contribution most
  likely to be reused, by being copied rather than cited.
+ *The suggestions* (@sec-suggest), in particular invalid ciphertexts in KAT sets, tagged KAT
  commits, canonical keys before binding, and context-binding every half. They are concrete and
  cheap to act on; their evidence is one project's experience.
+ *The HQC v5.1 port* (@sec-conf), for Rust users who need v5.1 today. It is reviewed only inside
  this project and should be replaced by an audited crate when one exists.
+ *The observations* (@sec-obs) and *the bounded-model-checking lessons* (@sec-bmc): practical,
  small, and mostly about tooling and process.

*What is re-confirmation.* That the concatenation-KDF combiner is not CCA-robust under ciphertext
mauling is the counterexample behind hashing ciphertexts in GHP18-style combiners
#cite-n("GHP18")\; that XOR fails even over sound components is folklore; that an AND-composite is
strongly unforgeable only if both components are, and that a standalone-valid half undermines a
composite under key reuse, are known in principle #cite-n("BHMS17", "MSS26"). Our contribution there
is the executable, reproducible form and the matrix across designs in one harness, not the insight.
VYRA's combiner showing no successful attack with one failed component is what the cited theorem
predicts for the technique; the experiment adds evidence that the _implementation_ hashes what the
design says, not evidence about the technique.

*What is new only as engineering.* The architecture, the dual post-quantum suites, the Ed25519ph
half, seed-only keys with suite-bound check values and the HQC port are careful engineering of
known techniques. None is a new construction.

*What would make this a stronger scientific result.*
- A written, reviewed proof for VYRA's exact encodings, in the ROM and QROM, including the binding
  notions of #cite-n("CDM23") for the combiner and the BUFF and non-separability notions for the
  composites, and the key-reuse model of #cite-n("MSS26").
- Larger $n$ (especially for the dual post-quantum pair), and adversaries that target the binding
  properties of the _real_ components, so that the negative control can fail.
- More failure models: validity oracles, partial key leakage, biased or correlated randomness,
  multi-user settings, MAL binding scenarios II and III.
- Constant-time verification of the glue and the HQC port with proper tooling on several CPUs.
- External review of the code, the experiment and this paper.
- Applying the method to X-Wing #cite-n("XWING"), the CFRG hybrid KEMs #cite-n("CFRG-HKEM") and
  RFC 10073 composites #cite-n("RFC10073") themselves. That would test designs others deploy, rather
  than our own, and is where the method would earn its keep.
