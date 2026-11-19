// VYRA research paper. Build: typst compile paper/vyra.typ paper/vyra.pdf
// Uses only fonts embedded in the Typst CLI (Libertinus Serif, New Computer
// Modern Math, DejaVu Sans Mono) and no external packages.
// Data tables read paper/data/*.typ, generated from results/ by paper/tools/gen_data.py.
#import "sections/common.typ": *

#set document(
  title: "VYRA: Testing Yielding Resistance in Hybrid Post-Quantum Constructions by Failure Injection",
  author: ("Encryptic1", "Trey Huffine"),
  date: datetime(year: 2026, month: 11, day: 19),
)

#set page(
  paper: "a4",
  margin: (x: 15mm, top: 17mm, bottom: 17mm),
  columns: 2,
  numbering: "1",
  number-align: center,
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 7.5pt, fill: luma(90))
      VYRA --- failure injection for hybrid constructions (research prototype) #h(1fr) November 2026
    ]
  },
)
#set columns(gutter: 6mm)
#set text(font: "Libertinus Serif", size: 9.5pt, lang: "en", region: "gb")
#set par(justify: true, leading: 0.52em, spacing: 0.7em)
#show math.equation: set text(font: "New Computer Modern Math")
#show raw: set text(font: "DejaVu Sans Mono", size: 0.92em)

#set heading(numbering: "1.1")
#show heading.where(level: 1): it => {
  set text(size: 10.8pt, weight: "bold")
  block(above: 1.0em, below: 0.55em, sticky: true, it)
}
#show heading.where(level: 2): it => {
  set text(size: 9.6pt, weight: "bold")
  block(above: 0.85em, below: 0.45em, sticky: true, it)
}
#show heading.where(level: 3): it => {
  set text(size: 9.5pt, weight: "bold", style: "italic")
  block(above: 0.75em, below: 0.4em, sticky: true, it)
}

#set figure(gap: 0.55em)
#show figure.caption: set text(size: 7.8pt)
#show figure.caption: set par(justify: false)
#show figure.where(kind: table): set figure.caption(position: top)
#show figure.where(kind: "algorithm"): set figure.caption(position: top)
#show figure: set block(breakable: false)
#set table(stroke: none, inset: (x: 2.6pt, y: 2pt))
#set footnote.entry(separator: line(length: 30%, stroke: 0.4pt))
#show footnote.entry: set text(size: 7.4pt)
#set list(indent: 0.5em, spacing: 0.5em)
#set enum(indent: 0.5em, spacing: 0.5em)

// ------------------------------------------------------------- title block
#place(top + center, float: true, scope: "parent", clearance: 1.1em)[
  #align(center)[
    #text(size: 16pt, weight: "bold")[VYRA: Testing Yielding Resistance in Hybrid \
      Post-Quantum Constructions by Failure Injection]
    #v(0.3em)
    #text(size: 10pt)[VYRA = Verified Yielding Resistance Architecture]
    #v(0.6em)
    #text(size: 10.5pt)[Encryptic1 and Trey Huffine]
    #v(0.05em)
    #text(size: 9pt)[Market Standard, LLC]
    #v(0.05em)
    #text(size: 9pt)[November 2026]
  ]
  #v(0.5em)
  #block(width: 100%, inset: (x: 7mm))[
    #set align(left)
    #set par(justify: true)
    #set text(size: 8.9pt)
    // Every number in this abstract is checked by paper/tools/check_numbers.py against
    // results/yield-matrix.json, results/kani-report.txt and the HQC KAT provenance.
    *Abstract.* Hybrid key encapsulation and composite signatures pair two components so that the
    construction keeps its security goal when one component is broken. We call this property
    _yielding resistance_. It is the reason hybrids exist, yet implementations are usually checked
    only for conformance of their components, which never exercises a broken component. We
    describe VYRA, a Rust research prototype whose components sit behind replaceable interfaces,
    and use it to test yielding resistance directly: deliberately broken models of the real
    components are plugged into the real composition code and attacked in explicit games, next to
    named insecure baselines, with positive and negative controls and a rule that expected verdicts
    follow stated claims, never observed results. In a deterministic matrix of 3365 cells (1955 KEM,
    1410 signature), no implemented attack won against VYRA's hybrid KEM combiner in any of the 230
    cells with exactly one failed component, while a concatenation-KDF combiner fell to ciphertext
    mauling and an XOR combiner fell even over two sound components. The same experiment exposed a
    weakness in our own earlier composite signature: because its Ed25519 half was a valid standalone
    signature, a modelled ML-DSA break plus a standalone Ed25519 signing oracle produced composite
    forgeries in 200 of 200 trials; binding every half to a composite context removed the attack
    in the same harness. Supporting work comprises bounded model checking of VYRA's own encodings
    (413 harnesses; 12 of 12 injected mutants killed), a pure-Rust port of HQC version 5.1 that
    reproduces all official known-answer vectors, and post-quantum pairs for both key
    establishment (ML-KEM + HQC) and signatures (ML-DSA + SLH-DSA). None of this is a security
    proof: verdicts are BROKEN or NO ATTACK FOUND against idealised failure models, there has been no
    external review, and constant-time behaviour is not verified.
  ]
  #v(0.45em)
  #block(width: 100%, stroke: 0.8pt, inset: 5.5pt, fill: luma(242))[
    #set align(left)
    #set text(size: 8pt)
    #set par(justify: true)
    *Status.* Research prototype (crates 0.1.0, wire version 1). No external review, audit or
    cryptanalysis by anyone outside the project; no written security proof for VYRA's concrete
    instantiation. HQC is implemented by VYRA's own port of the v5.1 specification (FIPS 207 is not
    published) and is checked only against the designers' vectors. Constant-time behaviour is not
    established. Not interoperable with X-Wing, the CFRG hybrid-KEM draft or RFC 10073. *Not for
    protecting real data.*
  ]
]

#include "sections/intro.typ"
#include "sections/name.typ"
#include "sections/related.typ"
#include "sections/architecture.typ"
#include "sections/method.typ"
#include "sections/results.typ"
#include "sections/encodings.typ"
#include "sections/conformance.typ"
#include "sections/performance.typ"
#include "sections/observations.typ"
#include "sections/value.typ"
#include "sections/closing.typ"
#include "sections/references.typ"
