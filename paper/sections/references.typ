#import "common.typ": *

// Source: docs/SECURITY.md §References (entries and verification markers, kept verbatim in
// substance), plus the HQC reference-implementation tag recorded in
// crates/vyra-hqc/tests/data/PROVENANCE.md. Only entries cited in this paper are listed.

#let refs = (
  "GHP18": ([F. Giacon, F. Heuer, B. Poettering. _KEM Combiners._ PKC 2018; Cryptology ePrint Archive, Paper 2018/024.], "verified online"),
  "DFH22": ([J. Don, S. Fehr, Y.-H. Huang. _Adaptive versus Static Multi-oracle Algorithms, and Quantum Security of a Split-key PRF._ TCC 2022; Cryptology ePrint Archive, Paper 2022/773.], "verified online"),
  "MSS26": ([L. Millerjord, D. Stebila, C. Steckel. _Split-key PRFs and Extended Hybrid Security for KEM Combiners._ IACR Communications in Cryptology, Vol. 2, No. 4, doi:10.62056/ah890lmol.], "verified online"),
  "BBFGS19": ([N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila. _Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange._ PQCrypto 2019, LNCS, doi:10.1007/978-3-030-25510-7\_12; Cryptology ePrint Archive, Paper 2018/903.], "verified online"),
  "XWING": ([M. Barbosa, D. Connolly, J. D. Duarte, A. Kaiser, P. Schwabe, K. Varner, B. Westerbaan. _X-Wing: The Hybrid KEM You've Been Looking For._ IACR Communications in Cryptology, doi:10.62056/a3qj89n4e; Cryptology ePrint Archive, Paper 2024/039.], "verified online"),
  "CFRG-HKEM": ([D. Connolly, R. Barnes, P. Grubbs. _Hybrid PQ/T Key Encapsulation Mechanisms._ draft-irtf-cfrg-hybrid-kems-12, 6 July 2026, work in progress.], "verified online"),
  "CDM23": ([C. Cremers, A. Dax, N. Medinger. _Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-based Protocols._ Cryptology ePrint Archive, Paper 2023/1933.], "verified online; later venue (ACM CCS 2024) from memory — verify"),
  "KSW25": ([J. Krämer, P. Struck, M. Weishäupl. _Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC._ IACR Communications in Cryptology, Vol. 2, No. 2 (2025), doi:10.62056/ak2i893y6; Cryptology ePrint Archive, Paper 2024/1233.], "verified online: bibliographic data and abstract; per-notion HQC results and the HQC version analysed not verified here"),
  "Sch24": ([S. Schmieg. _Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK._ Cryptology ePrint Archive, Paper 2024/523.], "verified online: title and main result as summarised by the ePrint listing"),
  "RFC10073": ([M. Ounsworth, J. Gray, M. Pala, J. Klaußner, S. Fluhrer. _Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for Use in X.509 Public Key Infrastructure._ RFC 10073, November 2026.], "verified online, IETF datatracker"),
  "BHMS17": ([N. Bindel, U. Herath, M. McKague, D. Stebila. _Transitioning to a Quantum-Resistant Public Key Infrastructure._ PQCrypto 2017.], "from memory — verify"),
  "CDFFJ21": ([C. Cremers, S. Düzlü, R. Fiedler, M. Fischlin, C. Janson. _BUFFing signature schemes beyond unforgeability and the case of post-quantum signatures._ IEEE S&P 2021, pp. 1696–1714; Cryptology ePrint Archive, Paper 2020/1525.], "verified online"),
  "DFF24": ([S. Düzlü, R. Fiedler, M. Fischlin. _BUFFing FALCON without Increasing the Signature Size._ SAC 2024, LNCS, pp. 131–150.], "verified online"),
  "CS03": ([R. Cramer, V. Shoup. _Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack._ SIAM Journal on Computing 33(1), 2003.], "from memory — verify"),
  "RFC9180": ([R. Barnes, K. Bhargavan, B. Lipp, C. Wood. _Hybrid Public Key Encryption._ RFC 9180, 2022.], "from memory — verify"),
  "FIPS202": ([NIST. _SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions._ FIPS PUB 202, 2015.], "from memory — verify"),
  "FIPS203": ([NIST. _Module-Lattice-Based Key-Encapsulation Mechanism Standard._ FIPS PUB 203, published 13 August 2024.], "verified online: publication date, via secondary sources"),
  "FIPS204": ([NIST. _Module-Lattice-Based Digital Signature Standard._ FIPS PUB 204, published 13 August 2024.], "verified online: publication date, via secondary sources"),
  "FIPS205": ([NIST. _Stateless Hash-Based Digital Signature Standard._ FIPS PUB 205, published 13 August 2024.], "verified online: publication date, via secondary sources; title from memory — verify"),
  "RFC8032": ([S. Josefsson, I. Liusvaara. _Edwards-Curve Digital Signature Algorithm (EdDSA)._ RFC 8032, 2017.], "from memory — verify"),
  "RFC8439": ([Y. Nir, A. Langley. _ChaCha20 and Poly1305 for IETF Protocols._ RFC 8439, 2018.], "from memory — verify"),
  "HQC-SPEC": ([C. Aguilar Melchor et al. (HQC team). _HQC specifications, version 5.1_, dated 2026/10/12 and 2026/11/09, pqc-hqc.org. Assumptions 2-DQCSD-P and 3-DQCSD-PT; IND-CCA2 in the ROM (Theorem 6.4); Table 8 parameters and DFR; changelog v5.0 → v5.1.], "verified online; author list from memory — verify"),
  "HQC-REF": ([HQC team. HQC reference implementation, gitlab.com/pqc-hqc/hqc, tag `v5.1.0` (commit `06567ccb`, "Release v5.1.0", 2026-10-26).], "fetched 2026-11-18; recorded in crates/vyra-hqc/tests/data/PROVENANCE.md"),
  "NIST-HQC": ([NIST. _NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption._ News release, 11 March 2025.], "verified online"),
  "CHLT26": ([K. Carrier, V. Hatey, L. Luzzi, J.-P. Tillich. _Multilevel Amortized Gaussian Elimination in Information-Set Decoding: Applications to HQC and PCG._ Cryptology ePrint Archive, Paper 2026/1498.], "verified online, as cited in HQC spec v5.1"),
  "RRCB20": ([P. Ravi, S. Sinha Roy, A. Chattopadhyay, S. Bhasin. _Generic Side-channel attacks on CCA-secure lattice-based PKE and KEMs._ IACR TCHES 2020(3), pp. 307–335.], "verified online"),
  "UXTITH22": ([R. Ueno, K. Xagawa, Y. Tanaka, A. Ito, J. Takahashi, N. Homma. _Curse of Re-encryption: A Generic Power/EM Analysis on Post-Quantum KEMs._ IACR TCHES 2022(1), pp. 296–322.], "verified online"),
)

= References <sec-refs>

#set text(size: 7.2pt)
#set par(justify: false, spacing: 0.45em)

Each entry ends with the verification status recorded in `docs/SECURITY.md` (bibliographic data
checked on 2026-11-18 against the publisher, IACR ePrint, the IETF datatracker or the project site,
or recorded from memory). Entries marked "from memory — verify" have not been checked online.

#v(0.2em)
#grid(
  columns: (5mm, 1fr),
  column-gutter: 1.2mm,
  row-gutter: 0.5em,
  ..ref-order.enumerate().map(((i, k)) => {
    let (body, status) = refs.at(k)
    ([[#(i + 1)]], [#body #text(style: "italic", fill: luma(80))[[#status]]])
  }).flatten(),
)
