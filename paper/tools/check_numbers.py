#!/usr/bin/env python3
"""Cross-check every number the paper quotes against the repository's result files.

Run from the repository root after compiling the paper:

    typst compile paper/vyra.typ paper/vyra.pdf
    python paper/tools/check_numbers.py

Checks:
  1. paper/data/*.typ are exactly what paper/tools/gen_data.py generates from results/.
  2. Every benchmark value printed in the PDF equals results/benchmarks.json, and the JSON
     equals results/benchmarks.md (median and p95, one decimal).
  3. Every size printed in the PDF equals results/sizes.json.
  4. Every yield-matrix count quoted in the text is recomputed from results/yield-matrix.json.
  5. Every Kani count is recomputed from results/kani-report.txt.
  6. Other quoted numbers are found verbatim in the repository file that is their source.
Exit status 0 iff there are no mismatches.
"""
import collections
import importlib.util
import json
import math
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
P = lambda *a: os.path.join(ROOT, *a)
mismatches = []
checks = []


def ok(desc, cond, detail=""):
    checks.append((desc, bool(cond), detail))
    if not cond:
        mismatches.append(f"{desc}: {detail}")


def read(*a):
    return open(P(*a), encoding="utf8").read()


# ------------------------------------------------------------------ sources
paper_src = "\n".join(
    read("paper", "sections", f) for f in sorted(os.listdir(P("paper", "sections"))) if f.endswith(".typ")
) + read("paper", "vyra.typ")
paper_flat = re.sub(r"\s+", " ", paper_src)

pdf = P("paper", "vyra.pdf")
try:
    pdf_text = subprocess.run(["pdftotext", "-enc", "UTF-8", "-layout", pdf, "-"], capture_output=True, check=True).stdout.decode("utf8", errors="replace")
except Exception as e:  # noqa: BLE001
    sys.exit(f"pdftotext failed: {e}")
pdf_flat = re.sub(r"\s+", " ", pdf_text)
pdf_flat = re.sub(r"\s*/\s*", "/", pdf_flat)  # pdftotext drops kerning spaces around "/"


def in_pdf(s):
    return re.sub(r"\s*/\s*", "/", s) in pdf_flat


def in_paper(s):
    return s in paper_flat or in_pdf(s)


# ------------------------------------------------------------------ 1. generated data is current
spec = importlib.util.spec_from_file_location("gen_data", P("paper", "tools", "gen_data.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
for name, fn in (("bench.typ", gen.gen_bench), ("sizes.typ", gen.gen_sizes_full), ("yield.typ", gen.gen_yield)):
    ok(f"paper/data/{name} equals regeneration from results/", read("paper", "data", name) == fn(), "stale data file")

# ------------------------------------------------------------------ 2. benchmarks
bj = json.load(open(P("results", "benchmarks.json"), encoding="utf8"))
rows = {(r["group"], r["name"], r["op"]): r for r in bj["results"]}
# md table
md = read("results", "benchmarks.md")
group = None
md_rows = {}
for line in md.splitlines():
    m = re.match(r"^## (\S+)", line)
    if m:
        group = m.group(1)
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if group and len(cells) == 8 and cells[0] not in ("name", "---"):
        md_rows[(group, cells[0], cells[1])] = cells
ok("benchmarks.md has the same rows as benchmarks.json", set(md_rows) == set(rows),
   f"{len(md_rows)} vs {len(rows)}")
for k, r in rows.items():
    c = md_rows.get(k)
    if c:
        ok(f"bench md==json {k}", c[3] == f"{r['median_us']:.1f}" and c[6] == f"{r['p95_us']:.1f}",
           f"md {c[3]}/{c[6]} json {r['median_us']}/{r['p95_us']}")

bench_quoted = 0
# Table: KEM suites and components (median, p95 of suites)
for s, a, b in (("VYRA-KEM-1", "ML-KEM-512", "HQC-128"), ("VYRA-KEM-3", "ML-KEM-768", "HQC-192"),
                ("VYRA-KEM-5", "ML-KEM-1024", "HQC-256")):
    for op in ("keygen", "encaps", "decaps"):
        vals = [f"{rows[('kem-component', a, op)]['median_us']:.1f}",
                f"{rows[('kem-component', b, op)]['median_us']:.1f}",
                f"{rows[('kem-suite', s, op)]['median_us']:.1f}",
                f"{rows[('kem-suite', s, op)]['p95_us']:.1f}"]
        line = " ".join(vals)
        ok(f"KEM bench row {s} {op} in PDF", in_pdf(line), line)
        bench_quoted += 4


def ms(us):
    # Typst calc.round: round half away from zero
    v = us / 1000
    r = math.floor(v * 100 + 0.5) / 100
    return f"{r:.2f}"


for s in ("VYRA-SIG-2", "VYRA-SIG-3", "VYRA-SIG-5", "VYRA-SIG-PQ1", "VYRA-SIG-PQ3", "VYRA-SIG-PQ5"):
    vals = [ms(rows[("sig-suite", s, op)]["median_us"]) for op in ("keygen", "sign-1KiB", "verify-1KiB")]
    line = f"{s} " + " ".join(vals)
    ok(f"SIG bench row {s} in PDF", in_pdf(line), line)
    bench_quoted += 3
for s in ("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256s"):
    vals = [ms(rows[("sig-component", s, op)]["median_us"]) for op in ("keygen", "sign-1KiB", "verify-1KiB")]
    line = f"{s} " + " ".join(vals)
    ok(f"SIG bench row {s} in PDF", in_pdf(line), line)
    bench_quoted += 3
# prose values
for (g, n, o, f) in (("kem-component", "HQC-256", "decaps", "p95_us"), ("kem-suite", "VYRA-KEM-5", "keygen", "min_us"),
                     ("seal", "VYRA-KEM-1", "seal-1KiB", "median_us")):
    v = f"{rows[(g, n, o)][f]:.1f}"
    ok(f"bench prose {n} {o} {f} = {v}", v + " µs" in pdf_flat, v)
    bench_quoted += 1
ok("bench date in PDF", bj["environment"]["date_utc"][:10] in pdf_flat, bj["environment"]["date_utc"])
ok("bench rustc in PDF", bj["environment"]["rustc"] in pdf_flat, bj["environment"]["rustc"])

# ------------------------------------------------------------------ 3. sizes
sj = json.load(open(P("results", "sizes.json"), encoding="utf8"))
size_quoted = 0
for c in sj["components"]:
    ct = c.get("ciphertext", c.get("signature"))
    line = f"{c['name']} {c['level']} {c['public_key']} {c['secret_key']} {ct}"
    ok(f"size row {c['name']} in PDF", in_pdf(line), line)
    size_quoted += 4
for k in sj["kem_suites"] + sj["sig_suites"]:
    r, w = k["raw"], k["wire"]
    ctk = "ciphertext" if "ciphertext" in r else "signature"
    line = (f"{k['suite']} {k['suite_id']} {k['level']} {r['public_key']} / {w['public_key']} "
            f"{r['secret_key']} / {w['secret_key']} {r[ctk]} / {w[ctk]}")
    ok(f"size row {k['suite']} in PDF", in_pdf(line), line)
    size_quoted += 7
seal = " / ".join(str(s["overhead"]) for s in sj["seal_suites"])
ok("seal overheads in PDF", in_pdf(seal), seal)
pk2 = [k for k in sj["sig_suites"] if k["suite"] in ("VYRA-SIG-2", "VYRA-SIG-PQ1")]
ok("1344-byte coincidence", all(k["raw"]["public_key"] == 1344 for k in pk2) and "1344 bytes" in paper_flat)
sigs = sorted(k["raw"]["signature"] for k in sj["sig_suites"] if k["family"] == "dual-pq")
ok("dual-PQ signatures 10–34 KB", sigs[0] // 1000 == 10 and round(sigs[-1] / 1000) == 34 and "10--34 KB" in paper_src,
   str(sigs))

# ------------------------------------------------------------------ 4. yield matrix
yj = json.load(open(P("results", "yield-matrix.json"), encoding="utf8"))
cells = yj["cells"]


def pair(c):
    if c["primitive"] == "kem":
        return "kem"
    return "pq" if c["component_2"].startswith("SLH-DSA") else "tr"


def nf(c):
    return (c["model_1"] != "Real") + (c["model_2"] != "Real")


cnt = collections.Counter(pair(c) for c in cells)
yq = []  # (description, quoted string, true value)
yq.append(("total cells", "3365", len(cells)))
yq.append(("KEM cells", "1955", cnt["kem"]))
yq.append(("signature cells", "1410", cnt["tr"] + cnt["pq"]))
yq.append(("transition cells", "1280", cnt["tr"]))
yq.append(("dual-PQ cells", "130", cnt["pq"]))
yq.append(("KEM trials", "200", yj["trials_per_cell"]))
yq.append(("sig trials", "200", yj["trials_per_cell_sig"]))
yq.append(("dual-PQ trials", "12", yj["trials_per_cell_sig_pq"]))
v1 = [c for c in cells if pair(c) == "kem" and c["combiner"] == "Vyra" and nf(c) == 1]
yq.append(("Vyra KEM one-failed cells", "230", len(v1)))
ok("Vyra KEM one-failed all NO ATTACK FOUND", all(c["verdict"] == "NO ATTACK FOUND" for c in v1))
unspec = sum(c["expected"] == "UNSPECIFIED" for c in cells)
yq.append(("UNSPECIFIED cells", "2606", unspec))
yq.append(("cells with expectation", "759", len(cells) - unspec))
yq.append(("UNSPECIFIED percent", "77%", f"{round(100 * unspec / len(cells))}%"))
ok("no cell contradicts its expectation",
   all(c["expected"] in ("UNSPECIFIED", c["verdict"]) for c in cells))
ctl = {}
for e in yj["controls"] + yj["claim_checks"] + yj["expectation_checks"]:
    ctl.setdefault(e["id"], e["cells_checked"])
    ok(f"control/check {e['id']} passed", e["passed"])
for cid, q in (("A", "15"), ("B", "92"), ("B-XOR", "23"), ("D", "85"), ("control:S-B", "101"),
               ("control:S-D", "80"), ("claim:yield-forgeable", "44"), ("claim:EUF", "30"), ("V1", "230")):
    yq.append((f"control {cid} cells", q, ctl[cid]))
cal, scal = yj["calibration"], yj["sig_calibration"]
yq.append(("calibration trials", "2000", cal["trials"]))
yq.append(("calibration wins", "1023", cal["wins"]))
yq.append(("sig calibration wins (0 of 2000)", "2000 trials: 0 wins", f"{scal['trials']} trials: {scal['wins']} wins"))


def pval(k, n, p):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))


minw = next(k for k in range(0, 201) if pval(k, 200, 0.5) < yj["alpha"])
yq.append(("min wins for BROKEN at n=200", "134", minw))
yq.append(("advantage threshold", "0.34", f"{2 * minw / 200 - 1:.2f}"))
ci200 = next(c["ci_high"] for c in cells if c["trials"] == 200 and c["wins"] == 0 and c["baseline"] < 1e-30)
ci12 = next(c["ci_high"] for c in cells if c["trials"] == 12 and c["wins"] == 0)
yq.append(("99% upper limit n=200", "0.032", f"{ci200:.3f}"))
yq.append(("99% upper limit n=12", "0.356", f"{ci12:.3f}"))
maxadv = max(c["advantage"] for c in cells if c["game"] == "IND-CCA2" and c["verdict"] == "NO ATTACK FOUND")
yq.append(("max IND-CCA2 advantage without verdict", "0.21", f"{maxadv:.2f}"))
yq.append(("Bonferroni bound", "3.4 dot 10^(-3)", f"{math.ceil(len(cells) * yj['alpha'] * 1e4) / 10:.1f} dot 10^(-3)"))
single = [c for c in cells if c["verdict"] == "BROKEN" and c["wins"] < c["trials"]]
ok("exactly two single-win BROKEN cells", len(single) == 2 and all(c["wins"] == 1 for c in single),
   str([(c["combiner"], c["game"], c["wins"]) for c in single]))
advs = collections.Counter()
for c in cells:
    advs[c["primitive"], c["adversary"]] += 0
yq.append(("KEM adversaries", "eleven for the KEM", f"{['', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven'][len({a for p, a in advs if p == 'kem'})]} for the KEM"))
yq.append(("sig adversaries", "fifteen for signatures",
           f"{ {15: 'fifteen'}.get(len({a for p, a in advs if p == 'sig'}), '?') } for signatures"))
pe = [c for c in cells if c["combiner"] == "VyraPureEd" and c["game"] == "STRIP-STANDALONE"
      and c["model_1"] == "Forgeable" and c["model_2"] == "Real"]
ok("VyraPureEd Fg x R STRIP-STANDALONE: all four Recombine 200/200",
   len(pe) == 4 and all(c["wins"] == 200 and c["trials"] == 200 for c in pe))

# summary table
squares = collections.defaultdict(bool)
for c in cells:
    squares[(pair(c), c["combiner"], c["model_1"], c["model_2"], c["game"])] |= c["verdict"] == "BROKEN"


def sq(p, d, k):
    ks = [x for x in squares if x[0] == p and x[1] == d and nf({"model_1": x[2], "model_2": x[3]}) == k]
    return f"{sum(squares[x] for x in ks)} / {len(ks)}"


summary_quoted = 0
for p, designs in (("kem", ["Naive", "Xor", "CtBound", "XWingStyle", "Vyra"]),
                   ("tr", ["Concat", "ConcatCtx", "Either", "VyraPureEd", "Vyra"]),
                   ("pq", ["Concat", "Vyra"])):
    for d in designs:
        parts = [sq(p, d, 0), sq(p, d, 1)] + ([sq(p, d, 2)] if p != "pq" else [])
        line = f"{d} " + " ".join(parts)
        ok(f"summary row {p}/{d} in PDF", in_pdf(line), line)
        summary_quoted += len(parts)
# prose restatements of summary counts
for desc, q, p, d in (("Naive one-failed", "28 of its 70", "kem", "Naive"), ("XWingStyle one-failed", "14 of 70", "kem", "XWingStyle"),
                      ("Vyra transition one-failed", "6 of the 90", "tr", "Vyra"), ("Vyra PQ one-failed", "2 of 32", "pq", "Vyra"),
                      ("Concat PQ one-failed", "20 of 32", "pq", "Concat"), ("Vyra KEM one-failed", "0 of 70", "kem", "Vyra")):
    nums = re.findall(r"\d+", q)
    truth = sq(p, d, 1).split(" / ")
    yq.append((desc, q, q if nums == truth else f"{truth[0]} of {truth[1]}"))

for desc, q, truth in yq:
    good = str(truth) == q or (isinstance(truth, int) and q == str(truth))
    present = in_paper(q)
    ok(f"yield: {desc} = {q}", good and present, f"truth {truth}, present {present}")

# key cells table: every (wins/trials) row of paper/data/yield.typ (regenerated in step 1) is in the PDF
yt = read("paper", "data", "yield.typ")
block = yt[yt.index("#let yield-key-cells"):]
for line in block.splitlines()[1:]:
    if not line.startswith("  ("):
        break
    toks = re.findall(r'"([^"]*)"|(\d+)', line)
    vals = [x or y for x, y in toks]
    pr, d, m1, m2, g, adv, w, t = vals[:8]
    cj = [c for c in cells if pair(c) == {"kem": "kem", "transition": "tr", "pq": "pq"}[pr] and c["combiner"] == d
          and c["model_1"] == m1 and c["model_2"] == m2 and c["game"] == g and c["adversary"] == adv]
    good = len(cj) == 1 and str(cj[0]["wins"]) == w and str(cj[0]["trials"]) == t
    ok(f"key cell {d} {m1}x{m2} {g} {adv} = {w}/{t}", good and in_pdf(f"{w}/{t}"), "")

# ------------------------------------------------------------------ 5. Kani
kr = read("results", "kani-report.txt")
summ = kr[kr.index("===== SUMMARY ====="):]
harn = re.findall(r"^harness\t(\S+)\t(\S+)\t\S+\tn=(\d+)", summ, re.M)
muts = re.findall(r"^mutant\t(\S+)\t(\S+)\t\S+\toutcome=(\S+)\texpected=(\S+)\t(\S+)", summ, re.M)
ok("Kani: 10 entries", len(harn) == 10 and "10 entries" in paper_flat, str(len(harn)))
ok("Kani: all SUCCESSFUL", all(h[1] == "SUCCESSFUL" for h in harn))
ok("Kani: 413 harnesses", sum(int(h[2]) for h in harn) == 413 and "413 harnesses" in paper_flat,
   str(sum(int(h[2]) for h in harn)))
ok("Kani: 12 mutants killed", len(muts) == 12 and all(m[2] == "killed" and m[4] == "OK" for m in muts)
   and "12 of 12" in paper_flat)
ok("Kani: overall exit status 0", "overall exit status: 0" in summ)
m = re.search(r"date \(UTC\):\s+(\S+)", kr)
ok("Kani: report date", m and m.group(1) in pdf_flat, m.group(1) if m else "?")
kani_quoted = 4
for name, _, n in harn:
    mt = sorted(x[0] for x in muts if x[1] == name)
    # the row of the Kani table in paper/sections/encodings.typ
    src_row = next((l for l in read("paper", "sections", "encodings.typ").splitlines()
                    if l.strip().startswith("[`" + name + "`")), "")
    want = f"[{n}], [{', '.join(mt)}]"
    ok(f"Kani row {name}: n={n}, mutants {','.join(mt)}", want in src_row, src_row[-40:])
    kani_quoted += 1 + len(mt)
kres = read("tools", "kani", "RESULTS.md")
for q in ("1079 s", "800 s"):
    ok(f"Kani runtime {q} in RESULTS.md and paper", q in kres and q in paper_flat)

# ------------------------------------------------------------------ 6. numbers found verbatim in their source
verbatim = [
    ("HQC KAT counts", "100", "crates/vyra-hqc/NOTICE.md", "all 100 counts"),
    ("HQC RS vectors per set", "200 official Reed", "docs/SECURITY.md", "200 official Reed–Solomon vectors per set"),
    ("HQC random round trips", "2000 random round trips", "docs/ATTEMPTS.md", "2000 random round trips per set"),
    ("ML-DSA ACVP keyGen", "keyGen (75)", "docs/SECURITY.md", "keyGen (75)"),
    ("ML-DSA ACVP sigGen", "sigGen (90", "docs/SECURITY.md", "sigGen (90"),
    ("ML-DSA ACVP sigVer", "sigVer (45)", "docs/SECURITY.md", "sigVer (45"),
    ("SLH-DSA ACVP keyGen", "keyGen (30)", "docs/SECURITY.md", "keyGen (30)"),
    ("SLH-DSA ACVP sigGen", "sigGen (42", "docs/SECURITY.md", "sigGen (42"),
    ("SLH-DSA ACVP sigVer", "sigVer (42)", "docs/SECURITY.md", "sigVer (42)"),
    ("Ed25519 context cases", "24 context cases", "docs/SECURITY.md", "24 context cases"),
    ("dalek non-canonical", "26 of 40", "docs/SECURITY.md", "26 of 40"),
    ("dalek mixed-order", "all 7", "docs/SECURITY.md", "all\n   7 constructed"),
    ("wire sk bit flips", "952", "docs/ATTEMPTS.md", "all 952 single-bit flips"),
    ("indexing sites", "152", "crates/vyra-hqc/NOTICE.md", "(152 sites in total)"),
    ("clmul multiplications", "25 ordinary", "crates/vyra-hqc/NOTICE.md", "25\n  integer multiplications"),
    ("HQC speed-up", "3.4--4.8", "docs/ATTEMPTS.md", "3.4–4.8x"),
    ("timing |t|", "below 1.6", "docs/SECURITY.md", "below\n  1.6"),
    ("timing samples", "1500--3000", "docs/SECURITY.md", "1500–3000"),
    ("enumeration round trip", "3,223,808", "docs/SECURITY.md", "3,223,808"),
    ("enumeration framing A", "66,306", "docs/SECURITY.md", "66,306"),
    ("enumeration framing B", "954,304", "docs/SECURITY.md", "954,304"),
    ("CBMC memory", "28--31 GB", "docs/SECURITY.md", "28–31 GB"),
    ("string 14 bytes", "14-byte", "tools/kani/RESULTS.md", "14-byte"),
    ("string 22 bytes", "22-byte", "tools/kani/RESULTS.md", "22-byte"),
    ("HQC weights", "67/101/132", "docs/SECURITY.md", "ω = 67 / 101 /\n  132"),
    ("HQC weights r", "76/114/150", "docs/SECURITY.md", "76 /\n  114 / 150"),
    ("combiner bytes", "8--25 KB", "docs/SECURITY.md", "8–25 KB"),
    ("yield runtime", "about 2 minutes", "docs/BUILDING.md", "about 2 minutes"),
    ("vectors runtime", "about 40 s", "docs/BUILDING.md", "about 40 s"),
    ("model test names", "models_break_what_they_say", "docs/SECURITY.md", "models_break_what_they_say"),
    ("Kani bound decode", "input length 0..=24", "tools/kani/RESULTS.md", "input length 0..=24"),
    ("Kani bound reader", "input length 0..=64, up to 5", "tools/kani/RESULTS.md", "input length 0..=64, sequences of up to 5 ops"),
    ("Kani bound round trip", "payload 0..=16", "tools/kani/RESULTS.md", "payload length 0..=16"),
    ("Kani bound header", "payload 0..=4", "tools/kani/RESULTS.md", "payload length 0..=4"),
    ("Kani bound single frame", "|x| ≤ 16, |rest| ≤ 16", "tools/kani/RESULTS.md", "len(x) ≤ 16, len(rest) ≤ 16"),
    ("Kani bound framing", "0..=3 fields of ≤ 3 bytes", "tools/kani/RESULTS.md", "0..=3 fields, each of length ≤ 3"),
    ("Kani bound ct_eq", "lengths 0..=8", "tools/kani/RESULTS.md", "lengths 0..=8 each"),
    ("Kani bound rng", "≤ 4 calls", "tools/kani/RESULTS.md", "≤ 4 calls"),
    ("Kani bound P6", "context and message 0..=6", "tools/kani/RESULTS.md", "context length 0..=6, message length 0..=6"),
    ("P6 prefix", "44-byte prefix", "tools/kani/RESULTS.md", "44-byte prefix"),
    ("composite context length", "12 B", "docs/SPEC.md", "12 bytes"),
    ("check value length", "16-byte check value", "docs/SPEC.md", "16-byte"),
    ("Kani tool versions", "Kani 0.68.0 with CBMC 6.11.0", "results/kani-report.txt", "CBMC 6.11.0"),
]
norm = lambda s: re.sub(r"\s+", " ", s)
for desc, q, src, needle in verbatim:
    ok(f"verbatim {desc}: '{q}' in paper and '{norm(needle)}' in {src}",
       (q in paper_src or q in paper_flat) and norm(needle) in norm(read(*src.split("/"))), "")
rules = [l for l in read("RULES.md").splitlines() if re.match(r"^\d+\. ", l)]
ok("RULES.md has 39 rules", len(rules) == 39 and "39 rules" in paper_flat, str(len(rules)))
att = [l for l in read("docs", "ATTEMPTS.md").splitlines() if l.startswith("| ") and not l.startswith("| Unit")]
att = att[:61]  # the paper counts "the first 61 rows"; later rows are appended after it is built
verd = collections.Counter(r.split("|")[3].strip() for r in att)
npass = sum(v for k, v in verd.items() if k.startswith("PASS"))
nfail = sum(v for k, v in verd.items() if k.startswith("FAIL"))
nother = len(att) - npass - nfail - verd.get("PARTIAL", 0)
ok("attempt log rows 61 / 42 PASS / 15 FAIL / 1 PARTIAL / 3 check rows",
   (len(att), npass, nfail, verd.get("PARTIAL", 0), nother) == (61, 42, 15, 1, 3)
   and "first 61 rows" in paper_flat and "42 PASS and 15 FAIL" in paper_flat,
   str((len(att), npass, nfail, verd.get("PARTIAL", 0), nother)))

# ------------------------------------------------------------------ report
n_ok = sum(1 for _, g, _ in checks if g)
print(f"checks: {len(checks)}, passed: {n_ok}, mismatches: {len(mismatches)}")
print(f"benchmark values quoted and checked: {bench_quoted}; size values: {size_quoted}; "
      f"yield summary values: {summary_quoted}; Kani values: {kani_quoted}")
for m in mismatches:
    print("MISMATCH:", m)
sys.exit(1 if mismatches else 0)
