#!/usr/bin/env python3
"""Generate VYRA's figures (SVG) from the committed result files.

Run from the repository root:

    python tools/figures/gen_figures.py            # write the figures
    python tools/figures/gen_figures.py --check    # exit 1 if a committed figure is stale

Reads only results/yield-matrix.json, results/sizes.json, results/benchmarks.json,
results/kani-report.txt and results/verification-report.json. Writes

    docs/figures/<name>-light.svg, docs/figures/<name>-dark.svg   (README)
    paper/figures/<name>.svg                                      (paper, print colours)

Python standard library only; the output is deterministic. Every number drawn
is computed from the result files here. Statements that a figure makes in words
about the data (for example "0 of 70") are asserted before drawing, so the
generator fails instead of drawing a figure the data no longer supports.

Colours: categorical slots and status red are a published colour-blind-checked
palette; BROKEN is never encoded by colour alone (it also carries a cross).
"NO ATTACK FOUND" is deliberately a pale neutral, never green: it is not a
statement of security.
"""
import json
import math
import os
import sys
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RES = os.path.join(ROOT, "results")

SANS = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
THEMES = {
    "light": dict(bg="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9",
                  axis="#c3c2b7", border="#e1e0d9", panel="#f3f2ee", s1="#2a78d6", s2="#eb6834",
                  s3="#1baf7a", crit="#d03b3b", naf="#cde2fb", de="#b9b8af", font=SANS, cw=0.49),
    "dark": dict(bg="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a",
                 axis="#52514e", border="#383835", panel="#262624", s1="#3987e5", s2="#d95926",
                 s3="#199e70", crit="#d03b3b", naf="#104281", de="#5c5b57", font=SANS, cw=0.49),
    "paper": dict(bg=None, ink="#000000", ink2="#333333", muted="#666666", grid="#dddddd",
                  axis="#999999", border="#999999", panel="#f2f2f2", s1="#2a78d6", s2="#eb6834",
                  s3="#1baf7a", crit="#a61e2e", naf="#dfe6ee", de="#b0b0b0",
                  font="'Libertinus Serif', serif", cw=0.50),
}
W = 880


def n1(x):
    """Coordinate formatting: at most one decimal, no trailing zero."""
    s = f"{x:.1f}"
    return s[:-2] if s.endswith(".0") else s


def thousands(n):
    return f"{n:,}"


class Svg:
    def __init__(self, theme, title, subtitle=None):
        self.t = THEMES[theme]
        self.theme = theme
        self.p = []
        self.title = title
        # The README variants carry their own title; in the paper the caption does.
        if theme == "paper":
            self.y0 = 8
        else:
            self.text(20, 30, title, size=15, weight=600)
            if subtitle:
                self.text(20, 49, subtitle, size=12, fill="ink2")
                self.y0 = 68
            else:
                self.y0 = 50

    def col(self, c):
        return self.t.get(c, c)

    def tw(self, s, size):
        return len(s) * size * self.t["cw"]

    def text(self, x, y, s, size=12, fill="ink", anchor="start", weight=None, italic=False,
             rotate=None):
        a = [f'x="{n1(x)}"', f'y="{n1(y)}"', f'font-size="{n1(size)}"', f'fill="{self.col(fill)}"']
        if anchor != "start":
            a.append(f'text-anchor="{anchor}"')
        if weight:
            a.append(f'font-weight="{weight}"')
        if italic:
            a.append('font-style="italic"')
        if rotate is not None:
            a.append(f'transform="rotate({rotate} {n1(x)} {n1(y)})"')
        self.p.append(f"<text {' '.join(a)}>{escape(s)}</text>")

    def wrap(self, s, size, maxw):
        out, cur = [], ""
        for word in s.split(" "):
            cand = word if not cur else cur + " " + word
            if self.tw(cand, size) <= maxw or not cur:
                cur = cand
            else:
                out.append(cur)
                cur = word
        if cur:
            out.append(cur)
        return out

    def para(self, x, y, s, size=12, maxw=200, fill="ink2", lh=1.35, anchor="start", weight=None):
        """Wrapped text; returns the y of the line after the last one."""
        for line in self.wrap(s, size, maxw):
            self.text(x, y, line, size=size, fill=fill, anchor=anchor, weight=weight)
            y += size * lh
        return y

    def note(self, x, y, s, size=11, maxw=848, fill="muted"):
        """Explanatory footer. The paper's captions carry this text, so it is omitted there."""
        if self.theme == "paper":
            return y - 12
        return self.para(x, y, s, size=size, maxw=maxw, fill=fill)

    def lines(self, x, y, ls, size=12, fill="ink2", lh=1.35, anchor="start"):
        for line in ls:
            self.text(x, y, line, size=size, fill=fill, anchor=anchor)
            y += size * lh
        return y

    def rect(self, x, y, w, h, fill="panel", stroke=None, rx=0, sw=1):
        a = f'x="{n1(x)}" y="{n1(y)}" width="{n1(w)}" height="{n1(h)}" fill="{self.col(fill)}"'
        if rx:
            a += f' rx="{n1(rx)}"'
        if stroke:
            a += f' stroke="{self.col(stroke)}" stroke-width="{n1(sw)}"'
        self.p.append(f"<rect {a}/>")

    def line(self, x1, y1, x2, y2, stroke="axis", sw=1, cap=None):
        a = (f'x1="{n1(x1)}" y1="{n1(y1)}" x2="{n1(x2)}" y2="{n1(y2)}" '
             f'stroke="{self.col(stroke)}" stroke-width="{n1(sw)}"')
        if cap:
            a += f' stroke-linecap="{cap}"'
        self.p.append(f"<line {a}/>")

    def circle(self, x, y, r, fill, ring=True):
        a = f'cx="{n1(x)}" cy="{n1(y)}" r="{n1(r)}" fill="{self.col(fill)}"'
        if ring:
            a += f' stroke="{self.surface()}" stroke-width="2"'
        self.p.append(f"<circle {a}/>")

    def surface(self):
        return self.t["bg"] or "#ffffff"

    def arrow(self, pts, stroke="ink2", sw=1.5):
        """Polyline with an arrow head at the last point."""
        d = "M" + " L".join(f"{n1(x)},{n1(y)}" for x, y in pts)
        self.p.append(f'<path d="{d}" fill="none" stroke="{self.col(stroke)}" '
                      f'stroke-width="{n1(sw)}" stroke-linejoin="round"/>')
        (x1, y1), (x2, y2) = pts[-2], pts[-1]
        ang = math.atan2(y2 - y1, x2 - x1)
        L, Wd = 8.0, 3.6
        bx, by = x2 - L * math.cos(ang), y2 - L * math.sin(ang)
        px, py = -math.sin(ang) * Wd, math.cos(ang) * Wd
        self.p.append(f'<path d="M{n1(x2)},{n1(y2)} L{n1(bx + px)},{n1(by + py)} '
                      f'L{n1(bx - px)},{n1(by - py)} Z" fill="{self.col(stroke)}"/>')

    def hbar(self, x0, x1, y, h, fill, round_end=True):
        """Horizontal bar from the baseline x0 to x1; rounded at the data end only."""
        w = x1 - x0
        if w <= 0:
            return
        r = 4 if (round_end and w >= 5) else 0
        if not r:
            self.rect(x0, y, w, h, fill=fill)
            return
        self.p.append(
            f'<path d="M{n1(x0)},{n1(y)} H{n1(x1 - r)} Q{n1(x1)},{n1(y)} {n1(x1)},{n1(y + r)} '
            f'V{n1(y + h - r)} Q{n1(x1)},{n1(y + h)} {n1(x1 - r)},{n1(y + h)} H{n1(x0)} Z" '
            f'fill="{self.col(fill)}"/>')

    def box(self, x, y, w, h, title=None, body=None, size=12, fill="panel", stroke="border",
            center=True, title_size=None):
        self.rect(x, y, w, h, fill=fill, stroke=stroke, rx=6)
        ts = title_size or size
        cx = x + w / 2 if center else x + 10
        anchor = "middle" if center else "start"
        yy = y + 8 + ts
        if title:
            self.text(cx, yy, title, size=ts, weight=600, anchor=anchor)
            yy += ts * 1.45
        for line in body or []:
            self.text(cx, yy, line, size=size - 1, fill="ink2", anchor=anchor)
            yy += (size - 1) * 1.38

    def chips(self, x, y, maxw, labels, size=11, fill="bg", emph=()):
        """Row-wrapped chips; returns the y below the last row."""
        cx, h = x, size + 9
        for lab in labels:
            w = self.tw(lab, size) + 14
            if cx + w > x + maxw and cx > x:
                cx = x
                y += h + 5
            on = lab in emph
            self.rect(cx, y, w, h, fill="s1" if on else (self.surface() if fill == "bg" else fill),
                      stroke=None if on else "axis", rx=h / 2)
            self.text(cx + w / 2, y + h / 2 + size * 0.36, lab, size=size, anchor="middle",
                      fill="#ffffff" if on else "ink")
            cx += w + 5
        return y + h

    def cross(self, x, y, s, color="#ffffff", sw=1.6):
        self.line(x - s, y - s, x + s, y + s, stroke=color, sw=sw, cap="round")
        self.line(x - s, y + s, x + s, y - s, stroke=color, sw=sw, cap="round")

    def verdict_cell(self, x, y, w, h, broken):
        if broken is None:
            self.rect(x + 0.5, y + 0.5, w - 1, h - 1, fill="none", stroke="grid", rx=2)
        elif broken:
            self.rect(x, y, w, h, fill="crit", rx=2)
            self.cross(x + w / 2, y + h / 2, min(w, h) * 0.2)
        else:
            self.rect(x, y, w, h, fill="naf", rx=2)

    def verdict_legend(self, x, y, size=11.5):
        self.verdict_cell(x, y - 11, 14, 14, True)
        self.text(x + 20, y, "BROKEN: an implemented attack won", size=size, fill="ink2")
        x2 = x + 20 + self.tw("BROKEN: an implemented attack won", size) + 22
        self.verdict_cell(x2, y - 11, 14, 14, False)
        self.text(x2 + 20, y, "no attack found (not a proof of security)", size=size, fill="ink2")
        return x2 + 20 + self.tw("no attack found (not a proof of security)", size)

    def finish(self, h):
        t = self.t
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {n1(h)}" width="{W}" '
                f'height="{n1(h)}" font-family="{t["font"]}" role="img">')
        out = [head, f"<title>{escape(self.title)}</title>"]
        if t["bg"]:
            out.append(f'<rect x="0.5" y="0.5" width="{W - 1}" height="{n1(h - 1)}" rx="10" '
                       f'fill="{t["bg"]}" stroke="{t["border"]}"/>')
        out.extend(self.p)
        out.append("</svg>")
        return "\n".join(out) + "\n"


# ------------------------------------------------------------------ data
def load_json(name):
    with open(os.path.join(RES, name), encoding="utf8") as f:
        return json.load(f)


KEM_ONE = ["Leaky", "Malleable", "KeySubstitutable", "Constant", "SenderKeyed"]
KEM_BOTH = [("Leaky", "Leaky"), ("Malleable", "Malleable"),
            ("KeySubstitutable", "KeySubstitutable"), ("Constant", "Constant"),
            ("SenderKeyed", "SenderKeyed"), ("Leaky", "Constant")]
KEM_GAMES = ["IND-CCA2", "HON-BIND-K-CT", "LEAK-BIND-K-CT", "MAL-BIND-K-CT",
             "HON-BIND-K-PK", "LEAK-BIND-K-PK", "MAL-BIND-K-PK"]
KEM_GAME_LABELS = ["IND-CCA2", "HON K-CT", "LEAK K-CT", "MAL K-CT", "HON K-PK", "LEAK K-PK",
                   "MAL K-PK"]
KEM_DESIGNS = [("Naive", "H(k1 ‖ k2)"), ("Xor", "k1 xor k2"), ("CtBound", "H(k1, k2, c1, c2)"),
               ("XWingStyle", "H(k1, k2, c2, pk2)"), ("Vyra", "H(suite, k, c, pk)")]
SIG_ONE = ["Forgeable", "Malleable", "KeySubstitutable", "ContextIgnoring", "MessageCollapsing"]
SIG_GAMES = ["EUF-CMA", "SUF-CMA", "STRIP-COMPOSITE", "STRIP-STANDALONE", "S-CEO", "MBS", "MIX",
             "CROSS-SUITE", "CROSS-CONTEXT"]
SHORT = {"KeySubstitutable": "KeySubst.", "ContextIgnoring": "ContextIgn.",
         "MessageCollapsing": "MessageColl."}


class Data:
    def __init__(self):
        self.y = load_json("yield-matrix.json")
        self.sizes = load_json("sizes.json")
        self.bench = load_json("benchmarks.json")
        self.verify = load_json("verification-report.json")
        with open(os.path.join(RES, "kani-report.txt"), encoding="utf8") as f:
            kani = f.read()
        summary = kani.split("===== SUMMARY =====")[-1].splitlines()
        hs = [l.split("\t") for l in summary if l.startswith("harness\t")]
        ms = [l.split("\t") for l in summary if l.startswith("mutant\t")]
        assert hs and all(h[2] == "SUCCESSFUL" for h in hs), "Kani summary: a harness is not SUCCESSFUL"
        self.kani_harnesses = sum(int(h[4].split("=")[1]) for h in hs)
        self.kani_mutants = len(ms)
        self.kani_killed = sum(1 for m in ms if "OK" in m and "outcome=killed" in m)
        self.cells = self.y["cells"]
        self.groups = {}
        for c in self.cells:
            self.groups.setdefault((self.pair(c), c["combiner"], c["model_1"], c["model_2"],
                                    c["game"]), []).append(c)

    @staticmethod
    def pair(c):
        if c["primitive"] == "kem":
            return "kem"
        return "pq" if c["component_2"].startswith("SLH-DSA") else "transition"

    def broken(self, pair, design, m1, m2, game):
        cs = self.groups.get((pair, design, m1, m2, game))
        if not cs:
            return None
        return any(c["verdict"] == "BROKEN" for c in cs)

    def one_failed_patterns(self, pair):
        pats = sorted({(c["model_1"], c["model_2"]) for c in self.cells if self.pair(c) == pair})
        return [p for p in pats if (p[0] == "Real") != (p[1] == "Real")]

    def squares(self, pair, design, patterns, games):
        """(broken, total) squares over patterns x games, skipping games not run."""
        vs = [self.broken(pair, design, a, b, g) for (a, b) in patterns for g in games]
        vs = [v for v in vs if v is not None]
        return sum(vs), len(vs)

    def cell(self, pair, design, m1, m2, game, adversary):
        cs = [c for c in self.groups[(pair, design, m1, m2, game)] if c["adversary"] == adversary]
        assert len(cs) == 1
        return cs[0]

    def bench_median(self, group, name, op):
        rs = [r for r in self.bench["results"] if (r["group"], r["name"], r["op"]) == (group, name, op)]
        assert len(rs) == 1, (group, name, op)
        return rs[0]["median_us"]

    def comp(self, name):
        return next(c for c in self.sizes["components"] if c["name"] == name)


# ------------------------------------------------------------------ figures
def fig_construction(d, theme):
    s = Svg(theme, "How VYRA combines two independent components",
            "Both constructions are built so that the result still holds if one component family fails.")
    y = s.y0
    # ---- (a) KEM
    s.text(20, y + 12, "a", size=13, weight=700)
    s.text(36, y + 12, "Hybrid key encapsulation (VYRA-KEM)", size=13, weight=600)
    y += 28
    s.box(20, y + 20, 150, 108, "Recipient public key",
          ["pk1 for ML-KEM", "pk2 for HQC"])
    s.box(232, y, 196, 62, "ML-KEM encapsulate", ["module lattices · FIPS 203"])
    s.box(232, y + 86, 196, 62, "HQC encapsulate", ["error-correcting codes · v5.1"])
    s.arrow([(170, y + 55), (201, y + 55), (201, y + 31), (232, y + 31)])
    s.arrow([(170, y + 93), (201, y + 93), (201, y + 117), (232, y + 117)])
    # combiner
    cx, cw_ = 520, 232
    s.rect(cx, y, cw_, 148, fill="panel", stroke="s1", rx=6, sw=1.5)
    s.text(cx + cw_ / 2, y + 21, "Combiner: one SHA3-256 hash", size=12, weight=600, anchor="middle")
    s.text(cx + cw_ / 2, y + 38, "over everything, each field length-prefixed", size=10.5,
           fill="ink2", anchor="middle")
    s.chips(cx + 14, y + 50, cw_ - 24, ["label", "suite id", "k1", "k2", "c1", "c2", "pk1", "pk2"],
            size=11)
    s.arrow([(428, y + 31), (520, y + 31)])
    s.arrow([(428, y + 117), (520, y + 117)])
    s.text(474, y + 24, "key k1, ct c1", size=10.5, fill="ink2", anchor="middle")
    s.text(474, y + 110, "key k2, ct c2", size=10.5, fill="ink2", anchor="middle")
    # public keys into the combiner
    s.arrow([(95, y + 128), (95, y + 172), (cx + cw_ / 2, y + 172), (cx + cw_ / 2, y + 148)])
    s.text(300, y + 166, "the public keys are hashed as well", size=10.5, fill="ink2", anchor="middle")
    # output
    s.arrow([(cx + cw_, y + 74), (790, y + 74)])
    s.box(790, y + 46, 70, 56, "K", ["32 bytes"], size=13)
    y += 196
    y = s.note(20, y, "The ciphertext sent is c1 ‖ c2. Because K depends on both ciphertexts and both "
           "public keys, changing any of them changes K. The draft design this project started from "
           "used K = KDF(k1 ‖ k2), which ties K to neither; the experiment below reproduces the "
           "attack on that draft (the Naive baseline).", size=11.5, maxw=840, fill="ink2") + 10
    s.line(20, y, W - 20, y, stroke="grid")
    y += 14
    # ---- (b) signature
    s.text(20, y + 12, "b", size=13, weight=700)
    s.text(36, y + 12, "Composite signature (VYRA-SIG)", size=13, weight=600)
    y += 28
    s.box(20, y + 28, 130, 62, "Message M", ["context string ctx"])
    mx, mw = 196, 268
    s.rect(mx, y, mw, 118, fill="panel", stroke="s1", rx=6, sw=1.5)
    s.text(mx + mw / 2, y + 21, "Message representative M′", size=12, weight=600, anchor="middle")
    s.text(mx + mw / 2, y + 38, "what both halves actually sign", size=10.5, fill="ink2",
           anchor="middle")
    s.chips(mx + 14, y + 50, mw - 24, ["label", "suite id", "hash of both public keys",
                                       "ctx length", "ctx", "M"], size=11)
    s.arrow([(150, y + 59), (mx, y + 59)])
    sx, sw_ = 510, 212
    s.box(sx, y - 6, sw_, 58, "ML-DSA sign", ["module lattices · FIPS 204"])
    s.box(sx, y + 70, sw_, 58, "Second half sign", ["Ed25519ph, or SLH-DSA (hash-based)"])
    s.arrow([(mx + mw, y + 45), (487, y + 45), (487, y + 23), (sx, y + 23)])
    s.arrow([(mx + mw, y + 73), (487, y + 73), (487, y + 99), (sx, y + 99)])
    s.box(768, y + 28, 92, 62, "s1 ‖ s2", ["valid only if", "both verify"], size=12)
    s.arrow([(sx + sw_, y + 23), (745, y + 23), (745, y + 48), (768, y + 48)])
    s.arrow([(sx + sw_, y + 99), (745, y + 99), (745, y + 72), (768, y + 72)])
    y += 148
    y = s.note(20, y, "Each half is also signed under a VYRA-specific context (label and suite id), so a "
           "half is not a valid standalone signature and a standalone signature is not a valid half. "
           "The transition suites pair ML-DSA with Ed25519; the dual post-quantum suites pair it "
           "with SLH-DSA, so two different post-quantum assumptions must both fail.",
           size=11.5, maxw=840, fill="ink2")
    return s.finish(y + 6)


def fig_method(d, theme):
    y_ = d.y
    kem = [c for c in d.cells if c["primitive"] == "kem"]
    sig = [c for c in d.cells if c["primitive"] == "sig"]

    def distinct(cs, key):
        return len({c[key] for c in cs})

    kem_models = len({c["model_1"] for c in kem} - {"Real"})
    sig_models = len({c["model_1"] for c in sig} - {"Real"})
    stated = [c for c in d.cells if c["expected"] != "UNSPECIFIED"]
    contradicted = [c for c in stated if c["verdict"] != c["expected"]]
    checks = y_["controls"] + y_["claim_checks"] + y_["expectation_checks"]
    assert all(k["passed"] for k in checks), "a control or claim check did not pass"
    assert not contradicted, "a cell contradicts its stated expectation"
    assert y_["alpha"] == 1e-06

    s = Svg(theme, "Failure injection: turning “survives one broken component” into a test",
            "A real component is replaced by a deliberately broken one, and the composition is attacked in an explicit security game.")
    y = s.y0
    bw, gap, x0 = 158, 14.5, 16
    steps = [
        ("1  Real components", ["ML-KEM-512, HQC-128,", "ML-DSA-44, Ed25519,", "SLH-DSA-SHAKE-128s"]),
        ("2  Break one property", [f"{kem_models} failure models for KEMs,", f"{sig_models} for signatures; each",
                                   "wraps the real component"]),
        ("3  Compose", [f"{distinct(kem, 'combiner')} KEM combiners and", f"{distinct(sig, 'combiner')} signature designs:",
                        "VYRA plus baselines"]),
        ("4  Attack", [f"{distinct(kem, 'game')} KEM and {distinct(sig, 'game')} signature",
                       f"games; {distinct(kem, 'adversary')} + {distinct(sig, 'adversary')} coded attackers;",
                       f"{y_['trials_per_cell']} seeded trials per cell"]),
        ("5  Decide by a fixed rule", ["exact binomial test,", "p below 0.000001: BROKEN,", "else NO ATTACK FOUND"]),
    ]
    for i, (title, body) in enumerate(steps):
        x = x0 + i * (bw + gap)
        s.box(x, y, bw, 92, title, body, size=12, title_size=12)
        if i:
            s.arrow([(x - gap + 1, y + 46), (x - 1, y + 46)])
    y += 116
    # what the design is compared against
    s.text(16, y + 4, "What keeps the test honest", size=12, weight=600)
    y += 16
    cw3 = (W - 32 - 2 * 14) / 3
    notes = [
        ("Designs that must break", "Named insecure baselines (plain concatenation, XOR) and "
         "patterns with both components broken. If these did not break, the harness would be blind."),
        ("Attackers that must lose", "A coin-flipping distinguisher and a garbage forger, and every "
         "attacker against two real components (except XOR, which theory says is broken)."),
        ("Expectations written first", f"{thousands(len(stated))} of {thousands(len(d.cells))} cells "
         "carry a verdict predicted from a documented claim, control or theorem. "
         f"{len(contradicted)} contradicted it. The rest are observations."),
    ]
    hmax = 0
    for i, (t, body) in enumerate(notes):
        x = 16 + i * (cw3 + 14)
        yy = s.para(x + 12, y + 40, body, size=11, maxw=cw3 - 24)
        hmax = max(hmax, yy - y)
    for i, (t, body) in enumerate(notes):
        x = 16 + i * (cw3 + 14)
        s.rect(x, y, cw3, hmax, fill="none", stroke="border", rx=6)
        s.text(x + 12, y + 21, t, size=12, weight=600)
    y += hmax + 22
    y = s.note(16, y, "A verdict of NO ATTACK FOUND means only that the coded attackers did not win "
           "against an idealised failure. It is evidence that can refute a design, not a proof that "
           "the design is secure.", size=11.5, maxw=848, fill="ink2")
    return s.finish(y + 6)


def fig_kem_matrix(d, theme):
    one = [(m, r) for m in KEM_ONE for r in (1, 2)]
    rows = [("both real", ("Real", "Real"))]
    rows += [((SHORT.get(m, m) + (" · ML-KEM" if side == 1 else " · HQC")),
              ((m, "Real") if side == 1 else ("Real", m))) for (m, side) in one]
    rows += [((SHORT.get(a, a) + " + " + SHORT.get(b, b)), (a, b)) for (a, b) in KEM_BOTH]
    blocks = [(0, 1, "Both components real"),
              (1, 11, "Exactly one component failed (failure model · which component)"),
              (11, 17, "Both components failed")]
    vy_b, vy_t = d.squares("kem", "Vyra", [r[1] for r in rows[1:11]], KEM_GAMES)
    assert (vy_b, vy_t) == (0, 70), "VYRA one-failure squares changed"
    n_cells = sum(len(d.groups[("kem", "Vyra", a, b, g)]) for (_, (a, b)) in rows[1:11]
                  for g in KEM_GAMES)

    s = Svg(theme, "KEM results: which combiner survives which failure",
            "Rows: what was broken on purpose. Columns: five ways to combine the two keys, each attacked in seven games.")
    y = s.y0
    lx, bx0, pitch, cell, bgap = 150, 158, 19, 17, 10
    bwid = 7 * pitch
    # headers
    for i, (name, formula) in enumerate(KEM_DESIGNS):
        x = bx0 + i * (bwid + bgap)
        cxm = x + (bwid - (pitch - cell)) / 2
        s.text(cxm, y + 12, "VYRA" if name == "Vyra" else name, size=12.5, weight=700, anchor="middle")
        s.text(cxm, y + 28, formula, size=10.5, fill="ink2", anchor="middle")
        for j, g in enumerate(KEM_GAME_LABELS):
            gx = x + j * pitch + cell / 2 + 3.5
            s.text(gx, y + 96, g, size=10, fill="ink2", rotate=-90)
    y += 104
    vy_box = None
    for (a, b, title) in blocks:
        s.text(16, y + 11, title, size=10.5, fill="muted", weight=600)
        y += 18
        ytop = y
        for (label, (m1, m2)) in rows[a:b]:
            s.text(lx - 6, y + cell / 2 + 4, label, size=11, fill="ink2", anchor="end")
            for i, (name, _) in enumerate(KEM_DESIGNS):
                x = bx0 + i * (bwid + bgap)
                for j, g in enumerate(KEM_GAMES):
                    s.verdict_cell(x + j * pitch, y, cell, cell, d.broken("kem", name, m1, m2, g))
            y += pitch
        if a == 1:
            vx = bx0 + 4 * (bwid + bgap)
            vy_box = (vx - 4, ytop - 4, bwid - (pitch - cell) + 8, y - ytop - (pitch - cell) + 8)
        y += 8
    s.rect(*vy_box, fill="none", stroke="ink", rx=4, sw=1.5)
    y += 12
    s.verdict_legend(16, y)
    y += 22
    s.rect(16, y - 11, 14, 14, fill="none", stroke="ink", rx=3, sw=1.5)
    s.text(36, y, f"Outlined: VYRA with exactly one failed component. {vy_b} of {vy_t} squares "
           f"broken ({n_cells} cells, 200 trials each).", size=11.5, fill="ink2")
    y += 22
    y = s.note(16, y, "A square is BROKEN if any coded attacker for that game won. Components: ML-KEM-512 "
           "and HQC-128. K-CT and K-PK are the key-binding games (HON, LEAK, MAL: honest, leaked or "
           "attacker-chosen secret keys). VYRA breaks only when both components lose "
           "confidentiality, where nothing is left to protect.", size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fig_summary(d, theme):
    panels = [
        ("KEM", "ML-KEM-512 + HQC-128", "kem", ["Naive", "Xor", "CtBound", "XWingStyle", "Vyra"],
         KEM_GAMES),
        ("Signatures, transition", "ML-DSA-44 + Ed25519", "transition",
         ["Concat", "ConcatCtx", "Either", "VyraPureEd", "Vyra"], SIG_GAMES),
        ("Signatures, dual post-quantum", "ML-DSA-44 + SLH-DSA-SHAKE-128s", "pq",
         ["Concat", "Vyra"], SIG_GAMES),
    ]
    # the six VYRA transition squares, named in the footnote
    tr = d.one_failed_patterns("transition")
    vy = [(a, b, g) for (a, b) in tr for g in SIG_GAMES if d.broken("transition", "Vyra", a, b, g)]
    suf = [v for v in vy if v[2] == "SUF-CMA"]
    ci = [v for v in vy if v[2] == "STRIP-COMPOSITE" and "ContextIgnoring" in v[:2]]
    assert len(vy) == 6 and len(suf) == 4 and len(ci) == 2, "VYRA transition squares changed"

    s = Svg(theme, "Broken squares when exactly one component has failed",
            "Share of (failure pattern × game) squares in which some coded attacker won. Lower is better.")
    y = s.y0
    pw = (W - 32 - 2 * 22) / 3
    lab_w, bar_w = 78, 104
    ymax = y
    for i, (title, sub, pair, designs, games) in enumerate(panels):
        x = 16 + i * (pw + 22)
        s.text(x, y + 12, title, size=12.5, weight=600)
        s.text(x, y + 28, sub, size=11, fill="ink2")
        yy = y + 46
        bx = x + lab_w
        s.line(bx, yy - 4, bx, yy + len(designs) * 24 - 6, stroke="axis")
        for dn in designs:
            b, t = d.squares(pair, dn, d.one_failed_patterns(pair), games)
            is_v = dn == "Vyra"
            s.text(bx - 8, yy + 11, "VYRA" if is_v else dn, size=11.5, anchor="end",
                   fill="ink" if is_v else "ink2", weight=700 if is_v else None)
            s.hbar(bx, bx + bar_w * b / t, yy, 14, "s1" if is_v else "de")
            s.text(bx + bar_w * b / t + 7, yy + 11, f"{b} / {t}", size=11.5,
                   fill="ink" if is_v else "ink2", weight=700 if is_v else None)
            yy += 24
        ymax = max(ymax, yy)
    y = ymax + 14
    s.rect(16, y - 10, 12, 12, fill="s1", rx=2)
    s.text(34, y, "VYRA's design", size=11.5, fill="ink2")
    s.rect(140, y - 10, 12, 12, fill="de", rx=2)
    s.text(158, y, "comparison design", size=11.5, fill="ink2")
    y += 22
    y = s.note(16, y, "VYRA's 6 broken transition squares are 4 strong-unforgeability (SUF-CMA) squares, "
               "a gap stated before the run, and 2 where the failed component ignores its context. "
               "VyraPureEd is VYRA's own earlier signature design, kept as a control. The dual "
               "post-quantum pair ran with 12 trials per cell, so its row is weak evidence.",
               size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fig_sigfix(d, theme):
    modes = ["Recombine-Default", "Recombine-EmptyCtx", "Recombine-ForeignCtx", "Recombine-SuiteCtx"]
    res = {}
    for dn in ("VyraPureEd", "Vyra"):
        cs = [d.cell("transition", dn, "Forgeable", "Real", "STRIP-STANDALONE", m) for m in modes]
        res[dn] = (cs[0]["wins"], cs[0]["trials"], sum(c["wins"] for c in cs),
                   sum(c["trials"] for c in cs), any(c["verdict"] == "BROKEN" for c in cs))
    assert res["VyraPureEd"][4] and not res["Vyra"][4], "sig-fix before/after no longer holds"
    assert res["VyraPureEd"][2] == res["VyraPureEd"][3] and res["Vyra"][2] == 0

    s = Svg(theme, "A weakness the experiment found in VYRA's own signature design, and the fix",
            "Setting: the lattice half (ML-DSA) is modelled as forgeable, and the Ed25519 key also signs ordinary messages elsewhere.")
    y = s.y0
    pw = (W - 32 - 20) / 2
    panels = [
        ("Before", "Ed25519 half was a plain Ed25519 signature over M′", "VyraPureEd",
         "An ordinary Ed25519 signature over M′ is exactly what the composite expected, so the "
         "attacker gets a valid half from the ordinary signer and forges the other."),
        ("After", "Ed25519 half is Ed25519ph bound to the composite's context", "Vyra",
         "The half must be signed under the context “VYRA-SIG-v1 ‖ suite”. An ordinary signature "
         "is not such a half, so the same attack assembles nothing that verifies."),
    ]
    hmax = 0
    for i, (tag, head, dn, why) in enumerate(panels):
        x = 16 + i * (pw + 20)
        w1, n1_, wall, nall, brk = res[dn]
        s.text(x + 14, y + 24, tag, size=11, fill="muted", weight=700)
        s.text(x + 14, y + 43, head, size=12, weight=600)
        # attack flow
        fy = y + 58
        hw = (pw - 28 - 12) / 2
        s.box(x + 14, fy, hw, 50, "Ed25519 half", ["from an ordinary signer"], size=11.5)
        s.box(x + 14 + hw + 12, fy, hw, 50, "ML-DSA half", ["forged (failure model)"], size=11.5)
        s.arrow([(x + 14 + hw / 2, fy + 50), (x + 14 + hw / 2, fy + 66), (x + pw / 2 - 30, fy + 66),
                 (x + pw / 2 - 30, fy + 80)])
        s.arrow([(x + pw - 14 - hw / 2, fy + 50), (x + pw - 14 - hw / 2, fy + 66),
                 (x + pw / 2 + 30, fy + 66), (x + pw / 2 + 30, fy + 80)])
        s.box(x + pw / 2 - 90, fy + 80, 180, 30, "Composite verifier", size=11.5)
        # outcome
        oy = fy + 128
        s.verdict_cell(x + 14, oy, 30, 30, brk)
        s.text(x + 56, oy + 24, f"{w1} / {n1_}", size=26, weight=600)
        tx = x + 56 + s.tw(f"{w1} / {n1_}", 26) + 14
        s.text(tx, oy + 12, "forgeries accepted", size=11.5, fill="ink2")
        s.text(tx, oy + 27, f"{wall} / {nall} over all four oracle modes", size=11, fill="muted")
        yy = s.para(x + 14, oy + 54, why, size=11, maxw=pw - 28)
        hmax = max(hmax, yy - y)
    for i in range(2):
        x = 16 + i * (pw + 20)
        s.rect(x, y, pw, hmax, fill="none", stroke="border", rx=6)
    y += hmax + 22
    s.verdict_legend(16, y)
    y += 20
    y = s.note(16, y, "Game STRIP-STANDALONE: the attacker has no composite signing oracle, only ordinary "
               "signing oracles on the component keys, and wins with any valid composite signature. "
               "The earlier design stays in the experiment as a control that must keep breaking.",
               size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fig_sizes(d, theme):
    groups = []
    for field, title in (("public_key", "KEM public key"), ("ciphertext", "KEM ciphertext")):
        rows = []
        for k in d.sizes["kem_suites"]:
            a, b = (d.comp(n)[field] for n in k["components"])
            assert a + b == k["raw"][field]
            rows.append((k["suite"], a, b))
        groups.append((title, rows))
    for fam, title in (("transition", "Signature, transition suites (ML-DSA + Ed25519)"),
                       ("dual-pq", "Signature, dual post-quantum suites (ML-DSA + SLH-DSA)")):
        rows = []
        for k in d.sizes["sig_suites"]:
            if k["family"] != fam:
                continue
            a, b = (d.comp(n)["signature"] for n in k["components"])
            assert a + b == k["raw"]["signature"]
            rows.append((k["suite"], a, b))
        assert len(rows) == 3
        groups.append((title, rows))
    top = max(a + b for _, rows in groups for (_, a, b) in rows)
    xmax = math.ceil(top / 10000) * 10000

    s = Svg(theme, "What the second component costs in bytes",
            "Raw encoded sizes; each bar is one object, split into its two components.")
    y = s.y0
    px0, px1 = 128, 786

    def X(v):
        return px0 + (px1 - px0) * v / xmax

    # legend
    s.rect(px0, y, 12, 12, fill="s1", rx=2)
    s.text(px0 + 18, y + 10.5, "lattice component (ML-KEM or ML-DSA)", size=11.5, fill="ink2")
    lx2 = px0 + 18 + s.tw("lattice component (ML-KEM or ML-DSA)", 11.5) + 24
    s.rect(lx2, y, 12, 12, fill="s2", rx=2)
    s.text(lx2 + 18, y + 10.5, "second component (HQC, Ed25519 or SLH-DSA)", size=11.5, fill="ink2")
    y += 26
    ytop = y
    nrows = sum(len(r) for _, r in groups)
    ybot = y + len(groups) * 22 + nrows * 22 + 4
    for v in range(0, xmax + 1, 10000):
        s.line(X(v), ytop, X(v), ybot, stroke="axis" if v == 0 else "grid")
        s.text(X(v), ybot + 15, "0" if v == 0 else f"{v // 1000}K", size=10.5, fill="muted",
               anchor="middle")
    for title, rows in groups:
        s.rect(16, y + 2, px0 - 20, 16, fill=s.surface())
        s.text(16, y + 15, title, size=11, fill="muted", weight=600)
        y += 22
        for (suite, a, b) in rows:
            s.text(px0 - 8, y + 11, suite, size=11.5, fill="ink2", anchor="end")
            xa = X(a)
            s.rect(px0, y, max(xa - px0 - 1, 0.5), 14, fill="s1")
            s.hbar(xa + 1, X(a + b), y, 14, "s2")
            s.text(X(a + b) + 7, y + 11, thousands(a + b), size=11.5, fill="ink")
            y += 22
    y = ybot + 34
    s.text((px0 + px1) / 2, y, "bytes (raw encoding; the wire format adds a 7-byte header)", size=11,
           fill="muted", anchor="middle")
    y += 22
    y = s.note(16, y, "HQC accounts for most of every KEM object, and SLH-DSA for most of every dual "
               "post-quantum signature. In the transition suites the Ed25519 half is 64 bytes, too "
               "thin to see at this scale.", size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fmt_time(us):
    if us >= 1e6:
        return f"{us / 1e6:.2f} s"
    if us >= 1e3:
        return f"{us / 1e3:.2f} ms"
    return f"{us / 1e3:.2f} ms"


def fig_perf_kem(d, theme):
    suites = [(k["suite"], k["components"]) for k in d.sizes["kem_suites"]]
    ops = ["keygen", "encaps", "decaps"]
    rows = []
    for (suite, (c1, c2)) in suites:
        for op in ops:
            rows.append((suite, op, d.bench_median("kem-suite", suite, op),
                         d.bench_median("kem-component", c1, op),
                         d.bench_median("kem-component", c2, op)))
    top = max(max(r[2], r[3], r[4]) for r in rows)
    xmax = math.ceil(top / 1000) * 1000
    env = d.bench["environment"]

    s = Svg(theme, "Hybrid KEM speed: the code-based half sets the pace",
            "Median wall-clock time per operation, hybrid and each component measured separately (n = 200).")
    y = s.y0
    px0, px1 = 150, 800

    def X(v):
        return px0 + (px1 - px0) * v / xmax

    s.rect(px0, y, 12, 12, fill="de", rx=2)
    s.text(px0 + 18, y + 10.5, "hybrid (VYRA-KEM)", size=11.5, fill="ink2")
    x2 = px0 + 18 + s.tw("hybrid (VYRA-KEM)", 11.5) + 24
    s.circle(x2 + 6, y + 6, 5, "s1", ring=False)
    s.text(x2 + 18, y + 10.5, "ML-KEM alone", size=11.5, fill="ink2")
    x3 = x2 + 18 + s.tw("ML-KEM alone", 11.5) + 24
    s.circle(x3 + 6, y + 6, 5, "s2", ring=False)
    s.text(x3 + 18, y + 10.5, "HQC alone", size=11.5, fill="ink2")
    y += 28
    ytop = y
    ybot = y + 3 * 20 + 9 * 22 + 2
    for v in range(0, xmax + 1, 1000):
        s.line(X(v), ytop, X(v), ybot, stroke="axis" if v == 0 else "grid")
        s.text(X(v), ybot + 15, str(v // 1000), size=10.5, fill="muted", anchor="middle")
    last = None
    for (suite, op, hyb, m1, m2) in rows:
        if suite != last:
            s.rect(16, y + 2, px0 - 20, 14, fill=s.surface())
            s.text(16, y + 14, suite, size=11, fill="muted", weight=600)
            y += 20
            last = suite
        s.text(px0 - 8, y + 11, op, size=11.5, fill="ink2", anchor="end")
        s.hbar(px0, X(hyb), y, 14, "de")
        s.circle(X(m1), y + 7, 5, "s1")
        s.circle(X(m2), y + 7, 5, "s2")
        s.text(max(X(hyb), X(m2) + 5) + 8, y + 11, fmt_time(hyb), size=11.5, fill="ink")
        y += 22
    y = ybot + 34
    s.text((px0 + px1) / 2, y, "milliseconds (labels: hybrid median)", size=11, fill="muted",
           anchor="middle")
    y += 22
    y = s.para(16, y, f"One machine ({env['cpu'].strip()}, {env['os']}), release build, wall-clock; not "
               "cycle-accurate and not a constant-time evaluation. Hybrid and components were timed "
               "in separate runs: where a component dot lies beyond its hybrid bar, that is "
               "run-to-run noise, not a faster hybrid. The HQC port is pure Rust without hardware "
               "carry-less multiplication.", size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fig_perf_sig(d, theme):
    suites = [(k["suite"], k["family"]) for k in d.sizes["sig_suites"]]
    ops = [("keygen", "s3", "key generation"), ("sign-1KiB", "s1", "sign"),
           ("verify-1KiB", "s2", "verify")]
    vals = {(su, op): d.bench_median("sig-suite", su, op) for su, _ in suites for op, _, _ in ops}
    lo, hi = 2, 7  # 10^2 us = 0.1 ms ... 10^7 us = 10 s
    assert all(10 ** lo < v < 10 ** hi for v in vals.values())
    slow = [vals[(su, "sign-1KiB")] for su, fam in suites if fam == "dual-pq"]
    assert min(slow) >= 1e6, "dual post-quantum signing is no longer in seconds"

    s = Svg(theme, "Signature speed: the price of two post-quantum assumptions",
            "Median wall-clock time on a 1 KiB message. Logarithmic axis: each gridline is ten times the previous one.")
    y = s.y0
    px0, px1 = 128, 800

    def X(us):
        return px0 + (px1 - px0) * (math.log10(us) - lo) / (hi - lo)

    lx = px0
    for (_, colr, name) in ops:
        s.circle(lx + 6, y + 6, 5, colr, ring=False)
        s.text(lx + 18, y + 10.5, name, size=11.5, fill="ink2")
        lx += 18 + s.tw(name, 11.5) + 24
    y += 28
    ytop = y
    ybot = y + 2 * 20 + 6 * 24 + 2
    ticks = ["0.1 ms", "1 ms", "10 ms", "100 ms", "1 s", "10 s"]
    for i, lab in enumerate(ticks):
        s.line(X(10 ** (lo + i)), ytop, X(10 ** (lo + i)), ybot, stroke="grid")
        s.text(X(10 ** (lo + i)), ybot + 15, lab, size=10.5, fill="muted", anchor="middle")
    last = None
    heads = {"transition": "Transition (ML-DSA + Ed25519)", "dual-pq": "Dual post-quantum (ML-DSA + SLH-DSA)"}
    for (su, fam) in suites:
        if fam != last:
            s.rect(16, y + 2, s.tw(heads[fam], 11) + 8, 14, fill=s.surface())
            s.text(16, y + 14, heads[fam], size=11, fill="muted", weight=600)
            y += 20
            last = fam
        s.text(px0 - 8, y + 12, su, size=11.5, fill="ink2", anchor="end")
        s.line(px0, y + 8, px1, y + 8, stroke="grid")
        for (op, colr, _) in ops:
            s.circle(X(vals[(su, op)]), y + 8, 5, colr)
        sv = vals[(su, "sign-1KiB")]
        s.text(X(sv) + 11, y + 12, fmt_time(sv), size=11.5, fill="ink")
        y += 24
    y = ybot + 34
    s.text((px0 + px1) / 2, y, "time per operation (labels: signing median)", size=11, fill="muted",
           anchor="middle")
    y += 22
    y = s.note(16, y, "Same machine and caveats as the KEM timings. n = 200, except dual post-quantum key "
               "generation (n = 20) and signing (n = 10). Dual post-quantum signing takes seconds "
               "because SLH-DSA signing does; verification stays in milliseconds. These suites fit "
               "low-rate, long-lived signatures such as releases and archives.",
               size=11, maxw=848, fill="muted")
    return s.finish(y + 6)


def fig_evidence(d, theme):
    v = d.verify["summary"]
    assert v["fail"] == 0 and v["not_run"] == 0 and v["pass"] == v["total"]
    assert d.kani_killed == d.kani_mutants
    rows = [
        ("Components", "ML-KEM, HQC, ML-DSA, SLH-DSA, Ed25519",
         "Official test vectors: the HQC v5.1 known-answer tests, NIST ACVP vectors for ML-DSA "
         "and SLH-DSA, RFC 8032 vectors for Ed25519; cross-checks against independent crates.",
         "That the components are secure or run in constant time. No independent HQC v5.1 "
         "implementation exists to compare against."),
        ("Compositions", "KEM combiner, composite signature",
         f"Failure injection: {thousands(len(d.cells))} cells of explicit security games against "
         "deliberately broken components, with positive and negative controls.",
         "A security proof. Only the coded attacks were tried, against idealised failures."),
        ("Encodings", "wire header, transcript framing, message representative",
         f"Bounded model checking with Kani: {d.kani_harnesses} proof harnesses pass and "
         f"{d.kani_killed} of {d.kani_mutants} injected bugs are caught; exhaustive enumeration "
         "of small domains.",
         "Anything outside VYRA's own encoding code, or beyond the stated bounds."),
        ("Repository", "build, tests, documentation claims",
         f"{v['total']} machine-evaluated gates, all passing, run by one command "
         "(cargo xtask verify).",
         "Security. The gates show functional correctness and hygiene. There has been no "
         "external review."),
    ]
    s = Svg(theme, "What “Verified” means here, layer by layer",
            "Every claim is tied to a check a machine can rerun. The right-hand column is what those checks do not show.")
    y = s.y0
    c1, c2, c3 = 16, 196, 560
    w1, w2, w3 = 164, 344, 304
    s.text(c1 + 12, y + 12, "LAYER", size=10.5, fill="muted", weight=700)
    s.text(c2, y + 12, "CHECKED BY", size=10.5, fill="muted", weight=700)
    s.text(c3, y + 12, "NOT SHOWN", size=10.5, fill="muted", weight=700)
    y += 22
    for (layer, what, how, limit) in rows:
        s.line(16, y, W - 16, y, stroke="grid")
        ya = s.para(c1 + 12, y + 22, layer, size=12.5, maxw=w1 - 16, fill="ink", weight=600)
        ya = s.para(c1 + 12, ya + 1, what, size=11, maxw=w1 - 16, fill="ink2")
        yb = s.para(c2, y + 22, how, size=11.5, maxw=w2 - 16, fill="ink")
        yc = s.para(c3, y + 22, limit, size=11.5, maxw=w3 - 8, fill="ink2")
        ye = max(ya, yb, yc)
        s.rect(c1, y + 8, 3, ye - y - 16, fill="s1", rx=1.5)
        y = ye + 2
    s.line(16, y, W - 16, y, stroke="grid")
    y += 22
    y = s.note(16, y, "None of this is formal verification of the cryptography, and none of it replaces "
               "review by people outside the project.", size=11.5, maxw=848)
    return s.finish(y + 6)


FIGURES = [
    ("evidence", fig_evidence, False),
    ("construction", fig_construction, True),
    ("method", fig_method, True),
    ("kem-matrix", fig_kem_matrix, False),
    ("summary", fig_summary, True),
    ("sig-fix", fig_sigfix, True),
    ("sizes", fig_sizes, False),
    ("perf-kem", fig_perf_kem, False),
    ("perf-sig", fig_perf_sig, True),
]


def build():
    d = Data()
    out = {}
    for name, fn, in_paper in FIGURES:
        out[f"docs/figures/{name}-light.svg"] = fn(d, "light")
        out[f"docs/figures/{name}-dark.svg"] = fn(d, "dark")
        if in_paper:
            out[f"paper/figures/{name}.svg"] = fn(d, "paper")
    return out


def main():
    check = "--check" in sys.argv[1:]
    files = build()
    stale = []
    for rel, text in sorted(files.items()):
        path = os.path.join(ROOT, *rel.split("/"))
        if check:
            try:
                with open(path, encoding="utf8", newline="") as f:
                    if f.read() != text:
                        stale.append(rel)
            except OSError:
                stale.append(rel + " (missing)")
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf8", newline="\n") as f:
                f.write(text)
            print("wrote " + rel)
    if check:
        if stale:
            sys.exit("stale figures (rerun tools/figures/gen_figures.py):\n  " + "\n  ".join(stale))
        print(f"{len(files)} figures match the result files")


if __name__ == "__main__":
    main()
