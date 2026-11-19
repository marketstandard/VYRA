// Shared helpers for the VYRA paper. Numbers never live here: tables and figures read
// the generated files in paper/data/ (paper/tools/gen_data.py, from results/), and
// every other number in the text is listed and checked in paper/tools/check_numbers.py.

// ---------------------------------------------------------------- citations
// Order of the reference list (sections/references.typ). Keys follow
// docs/SECURITY.md §References; only cited entries are listed.
#let ref-order = (
  "GHP18", "DFH22", "MSS26", "BBFGS19", "XWING", "CFRG-HKEM", "CDM23", "KSW25", "Sch24",
  "RFC10073", "BHMS17", "CDFFJ21", "DFF24", "CS03", "RFC9180",
  "FIPS202", "FIPS203", "FIPS204", "FIPS205", "RFC8032", "RFC8439",
  "HQC-SPEC", "HQC-REF", "NIST-HQC", "CHLT26", "RRCB20", "UXTITH22",
)

#let refnum(k) = {
  let i = ref-order.position(x => x == k)
  assert(i != none, message: "unknown reference key " + k)
  str(i + 1)
}

// Numeric citation, e.g. #cite-n("GHP18", "DFH22") -> [1, 2]
#let cite-n(..keys) = "[" + keys.pos().map(refnum).join(", ") + "]"

// ---------------------------------------------------------------- colours
#let c-broken = rgb("#a61e2e")
#let c-ok = rgb("#dfe6ee")
#let c-na = white
#let c-head = luma(235)

// ---------------------------------------------------------------- boxes
#let algo(caption, body, placement: auto) = figure(
  placement: placement,
  kind: "algorithm",
  supplement: [Algorithm],
  caption: caption,
  block(
    width: 100%,
    stroke: 0.6pt,
    inset: (x: 4pt, y: 4pt),
    breakable: false,
    { show raw: set text(size: 6.5pt); align(left, body) },
  ),
)

#let note-box(title, body) = block(
  width: 100%,
  stroke: (left: 2pt + luma(90), rest: 0.4pt + luma(150)),
  fill: luma(245),
  inset: 5pt,
  [*#title* #body],
)

// Small table text helper
#let tsmall(body) = { set par(justify: false); text(size: 7.4pt, body) }

// Evidence-class tag used in the contributions list
#let tag(s) = box(
  fill: luma(232), inset: (x: 2pt, y: 0.5pt), outset: (y: 1pt), radius: 1pt,
  text(size: 7pt, weight: "medium", s),
)

// ---------------------------------------------------------------- heat maps
// Abbreviations of failure models in row labels.
#let model-abbr = (
  "Real": "R", "Leaky": "Lk", "Malleable": "Ml", "KeySubstitutable": "KS",
  "Constant": "Cn", "SenderKeyed": "SK", "Forgeable": "Fg", "ContextIgnoring": "CI",
  "MessageCollapsing": "MC",
)

#let hm-cell(code, w, h) = {
  let na = code == "-"
  let broken = code.starts-with("B")
  let pre = code.ends-with("*")
  let fill = if na { c-na } else if broken { c-broken } else { c-ok }
  box(
    width: w, height: h, fill: fill,
    stroke: if na { 0.3pt + luma(170) } else { none },
    align(center + horizon, if na {
      text(size: 5pt, fill: luma(120))[--]
    } else if pre {
      circle(radius: 0.62pt, fill: if broken { white } else { black }, stroke: none)
    }),
  )
}

// data: dictionary design -> array of rows (one per pattern) of cell codes.
// designs: array of (key, label). games: array of short labels.
// groups: number of rows in each block (separated by a gap), e.g. (1, 10, 6).
#let heatmap(data, designs, patterns, games, groups, cell-w: 3.6mm, cell-h: 3.1mm,
             label-w: 13mm, gap: 1.6mm) = {
  let ng = games.len()
  let cols = (label-w,)
  for (i, _) in designs.enumerate() {
    if i > 0 { cols.push(gap) }
    for _ in games { cols.push(cell-w) }
  }
  let cells = ()
  // header row 1: design names
  cells.push([])
  for (i, (key, label)) in designs.enumerate() {
    if i > 0 { cells.push([]) }
    cells.push(grid.cell(colspan: ng, align(center + bottom,
      text(size: 6.4pt, weight: "bold", label))))
  }
  // header row 2: rotated game labels
  cells.push(align(right + bottom, text(size: 5.6pt, style: "italic")[pattern]))
  for (i, _) in designs.enumerate() {
    if i > 0 { cells.push([]) }
    for g in games {
      cells.push(align(center + bottom, rotate(-90deg, reflow: true,
        text(size: 5.4pt, g))))
    }
  }
  // body
  let row-index = 0
  let block-ends = ()
  let acc = 0
  for g in groups { acc += g; block-ends.push(acc) }
  for (r, (m1, m2)) in patterns.enumerate() {
    let lab = model-abbr.at(m1) + " × " + model-abbr.at(m2)
    cells.push(align(right + horizon, text(size: 5.8pt, lab)))
    for (i, (key, _)) in designs.enumerate() {
      if i > 0 { cells.push([]) }
      for code in data.at(key).at(r) { cells.push(hm-cell(code, cell-w, cell-h)) }
    }
  }
  // row gutters: thin space normally, larger between blocks
  let nrows = 2 + patterns.len()
  let rg = ()
  for y in range(nrows - 1) {
    let body-r = y - 2 + 1 // number of body rows above the gutter
    if y == 0 { rg.push(0.6mm) } else if y == 1 { rg.push(0.8mm) }
    else if block-ends.contains(body-r) { rg.push(1.4mm) } else { rg.push(0.35mm) }
  }
  grid(columns: cols, column-gutter: 0.35mm, row-gutter: rg, ..cells)
}

#let hm-sw(code) = box(baseline: 20%, hm-cell(code, 3mm, 2.6mm))
#let hm-legend = text(size: 6.6pt)[
  #hm-sw("B") BROKEN (some implemented adversary wins) #h(0.8em)
  #hm-sw("N") NO ATTACK FOUND #h(0.8em)
  #hm-sw("N*") #hm-sw("B*") dot: pre-stated expectation (claim, control or theory); no dot:
  observation #h(0.8em)
  #hm-sw("-") not run
]

// ---------------------------------------------------------------- data access
#let bench-row(rows, group, name, op) = {
  let r = rows.find(r => r.at(0) == group and r.at(1) == name and r.at(2) == op)
  assert(r != none, message: "missing benchmark row " + group + "/" + name + "/" + op)
  r
}

// Convert a microsecond string (one decimal) to a millisecond string with two decimals.
#let us-to-ms(s) = {
  let v = float(s) / 1000
  let r = calc.round(v, digits: 2)
  let t = str(r)
  if not t.contains(".") { t + ".00" } else if t.split(".").at(1).len() == 1 { t + "0" } else { t }
}

// Identifier that may break after underscores
#let tname(s) = raw(s.replace("_", "_\u{200B}"))
