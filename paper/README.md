# VYRA paper

Typst source of the paper "VYRA: Testing Yielding Resistance in Hybrid
Post-Quantum Constructions by Failure Injection".

## Build

From the repository root, with Typst 0.15 (tested with 0.15.1):

    typst compile paper/vyra.typ paper/vyra.pdf

The build is offline and reproducible: the paper imports no `@preview/...`
packages and uses only the fonts embedded in the Typst CLI (Libertinus Serif,
New Computer Modern Math, DejaVu Sans Mono). Compiling twice gives a
byte-identical PDF. To confirm that no system font is used:

    typst compile --ignore-system-fonts paper/vyra.typ paper/vyra.pdf

To render pages as images for inspection:

    typst compile --ppi 110 paper/vyra.typ "out/p-{0p}.png"

## Layout

| file | contents |
|------|----------|
| `vyra.typ` | page setup, title block, abstract, status box; includes the sections |
| `sections/common.typ` | helpers: citations, algorithm boxes, heat maps, data lookups |
| `sections/intro.typ` ... `sections/closing.typ` | the sections, in order (see the `#include` list in `vyra.typ`) |
| `sections/references.typ` | the reference list with the verification status of each entry |
| `data/*.typ` | GENERATED data (benchmarks, sizes, yield-matrix grids); do not edit |
| `figures/*.svg` | GENERATED diagrams and charts (`tools/figures/gen_figures.py`, from `results/`); do not edit |
| `tools/gen_data.py` | writes `data/*.typ` from `results/` |
| `tools/check_numbers.py` | cross-checks every quoted number against `results/` and the other source files |

## Where the numbers come from

Tables and figures read `data/*.typ`, which `tools/gen_data.py` generates from:

- benchmarks: `results/benchmarks.json` (one decimal, exactly as printed in
  `results/benchmarks.md`; the signature table converts to milliseconds at
  build time)
- sizes: `results/sizes.json`
- failure-injection verdicts: `results/yield-matrix.json` (heat maps aggregate
  cells over adversaries; the key-cell table quotes individual cells)

Numbers quoted in the text are checked by `tools/check_numbers.py` against
`results/yield-matrix.json`, `results/kani-report.txt`, `tools/kani/RESULTS.md`,
`docs/SECURITY.md`, `docs/ATTEMPTS.md`, `RULES.md` and the other files named in
the script. Each table in the source carries a comment naming its source.

If `results/` is regenerated:

    python paper/tools/gen_data.py
    python tools/figures/gen_figures.py
    typst compile paper/vyra.typ paper/vyra.pdf
    python paper/tools/check_numbers.py    # needs pdftotext; exit 0 = no mismatch

The SVG figures name `Libertinus Serif` as their font, so they also render with
the embedded fonts only. `python tools/figures/gen_figures.py --check` exits 1
if a committed figure no longer matches `results/`.

Text that restates results (e.g. counts in the prose) must then be re-read; the
checker reports any quoted number that no longer matches.
