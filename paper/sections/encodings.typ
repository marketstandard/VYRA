#import "common.typ": *

= Machine-checked encodings <sec-bmc>

The experiment trusts that VYRA's composition code hashes what the design says. That rests on its
own encodings: the wire header and bounds-checked reader, the transcript framing, constant-time
equality's functional behaviour, the entropy adapter's failure latching and the signature message
layout. These are checked by exhaustive enumeration over stated finite domains and by bounded model
checking with Kani (decision D-18; `tools/kani/RESULTS.md`). None of this covers SHA-3, the
component algorithms, timing or zeroisation.

== Bounded model checking

Kani 0.68.0 with CBMC 6.11.0 (solver CaDiCaL) ran in a pinned container image; the report
(`results/kani-report.txt`, dated 2026-11-19T07:28:08Z) ends with overall exit status 0. All 10
entries (413 harnesses) are SUCCESSFUL and all 12 mutants are killed (@tab-kani). Entries marked
$star$ consist of one harness per length _shape_: every combination of concrete lengths up to the
bound, with fully symbolic contents, so that the union of the shapes is exactly the stated domain.
The run took 1079 s end to end, about 800 s of it verification.

// Source: results/kani-report.txt (SUMMARY block) and tools/kani/RESULTS.md (bounds, properties).
#figure(
  placement: top,
  scope: "parent",
  caption: [Bounded model checking of VYRA's encodings. Each row reads: "bounded model checking of
    _property_ up to _bound_"; nothing beyond the bound is covered.],
  tsmall(table(
    columns: (auto, 1.7fr, 1.25fr, auto, auto),
    align: (left, left, left, right, left),
    table.hline(stroke: 0.6pt),
    table.header([*Entry*], [*Property*], [*Exact bound*], [*Harn.*], [*Mutants*]),
    table.hline(stroke: 0.4pt),
    [`wire_decode_exact`], [decode is total; Ok exactly when magic, version and type match; returns the suite byte and exactly the payload; otherwise the exact error class], [input length 0..=24, all byte values, all 7 types], [1], [M1],
    [`wire_reader_ops`], [every reader operation total; `take(n)` for any `usize` n returns exactly the next n bytes or the exact error, reader unchanged; `finish` Ok iff all consumed], [input length 0..=64, up to 5 operations], [1], [M2, M3],
    [`wire_round_trip` $star$], [encode layout exact; decode(encode(t,s,p),u) is Ok((s,p)) iff t = u, else the exact error], [payload 0..=16 bytes, all suite bytes, all 49 (t,u) pairs], [17], [M4],
    [`wire_header_rejection`], [decode Ok exactly for canonical magic, version, type (all $2^56$ headers symbolic)], [payload 0..=4 bytes], [1], [M5],
    [`transcript_prefix_inverse`], [the 8-byte length prefix decodes back to n], [*every* `usize` n; x length ≤ 2], [1], [M8],
    [`transcript_single_frame`], [take_frame(push_frame(x) ‖ rest) = (x, rest) as exact subslices], [|x| ≤ 16, |rest| ≤ 16], [1], [M6],
    [`transcript_framing_shape` $star$], [an independent reference parser inverts the framed encoding, hence injectivity], [label ≤ 3 bytes; 0..=3 fields of ≤ 3 bytes], [340], [M7],
    [`secret_ct_eq_correct`], [`ct_eq` equals byte equality, both orders, no panic on unequal lengths], [lengths 0..=8 each], [1], [M9],
    [`rng_adapter_latches_failure`], [adapter never panics; outputs equal the source's bytes before a failure and are zero from the failing call on; source never called again; `finish` errors iff a call failed], [≤ 4 calls, buffers ≤ 8 bytes, every failure pattern], [1], [M10, M11],
    [`sig_message_representative` $star$], [the real representative function succeeds; its 44-byte prefix sits at fixed offsets; a reference parser recovers (suite, digest, context, message), hence injectivity], [context and message 0..=6 bytes, all suite bytes, all $2^256$ digests], [49], [M12],
    table.hline(stroke: 0.6pt),
  )),
) <tab-kani>

*What the framing result states.* Three lemmas: (1) for _every_ `usize` length $n$, the prefix of
$n$ decodes to $n$, so the prefix encoding is injective for all lengths; (2) for $|x|, |"rest"| <=
16$, `take_frame` applied to `push_frame(x) ‖ rest` returns exactly $(x, "rest")$; (3) for labels of
at most 3 bytes and at most 3 fields of at most 3 bytes, an independent reference parser is a left
inverse of the framed encoding, which implies injectivity on that domain. Extending (2) and (3) to
longer inputs is a _hand argument_ (the parser reads the length, which (1) proves correct for every
length, and splits there), not a machine-checked result.

*Exhaustive enumeration.* Host tests in `crates/vyra-proofs` enumerate, among others, every wire
round trip over 49 type pairs, 256 suite bytes and payloads of length 0 or 1 (3,223,808 cases) and
the framing injectivity over 66,306 plus 954,304 label--field sequences. They run on any machine
without Kani (gate V1).

== Mutation testing of the proofs

Each of 12 mutants is applied to a scratch copy and run against its entry. A mutant counts as
killed only if a _property_ assertion fails; a failure that is only an unwinding assertion would be
an unexpected outcome, because it says the bound was too small, not that the property caught the
defect (RULES 39). All 12 were killed by property assertions. The informative one is *M8*, which
keeps only the low byte of the length prefix. It survived the host enumeration (whose lengths are
all below 256) and every bounded content proof, because no bounded harness reaches a length of 256
or more. Only lemma (1), proven for all lengths separately from the content proofs, kills it. The
general lesson is small but real: a bounded proof of a length-prefixed encoding must state the
largest length it covers, and fixed-width prefix arithmetic should be proven for every length on
its own (RULES 33, 38).

*Practical lessons.* Two problems cost most of the effort, and neither was a defect in VYRA. First,
two harnesses failed in the first run only on unwinding assertions: comparing `&'static str` values
inside error values (the 14-byte "trailing bytes", the 22-byte "unexpected object type") needs more
unwindings than the loops themselves, so unwind bounds must be sized from the longest object
compared (RULES 36). Second, symbolic slice lengths made CBMC exhaust about 28--31 GB of memory;
enumerating concrete length shapes with symbolic contents solved it in seconds per shape, with the
shape list generated and checked against the stated bound (RULES 37). No run found a counterexample
to any property.

*Not covered.* SHA3-256 and SHAKE256 (assumed collision resistant), the components, timing,
zeroisation (the `ct_eq` harness skips `Drop`, because Kani does not support zeroize's
inline-assembly barrier), the public-key digest, signature contexts of 7 to 255 bytes, and every
input beyond the stated bounds.
