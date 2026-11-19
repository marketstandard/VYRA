# VYRA rules

One line per rule. A rule is added only after a fix that it explains has passed its check.

1. A hybrid KEM combiner must hash both component ciphertexts, not only the component shared secrets (see docs/DECISIONS.md D-01).
2. Never wrap, tweak, or strip checks from a standardised primitive; use it unmodified or not at all.
3. Never state a security property in docs that no proof or cited analysis supports.
4. Before trusting a component crate's version claim, compare its known-answer vectors with the official repository at a tagged release; an untagged commit is not a standard.
5. Run a differential test against a second implementation only after confirming both implement the same specification version.
6. When serialized objects have the same length in every suite, the wire form must bind the suite with a check value compared in constant time on parse; length cannot tell suites apart.
7. Public data that a secret key determines must be derived from the secret at use, never stored beside it; stored copies can disagree.
8. A composite signature's message representative must bind the whole composite public key, or halves from different signers recombine.
9. Where a component signature scheme has a context input, the composite must use a non-empty composite-specific context so its half is not a valid standalone signature.
10. Before asserting that tampering with a secret is detected, list which bits of the secret the standard actually reads on the path under test.
11. A test that asserts only a marker trait or iterates an empty collection cannot fail; say "verified by inspection" instead of counting it as a test.
12. Before hashing public-key bytes into a binding, require the canonical encoding (decode, re-encode, compare); do not assume the upstream decoder rejects non-canonical input.
13. Keep each suite-to-component mapping in exactly one function and make every constructor go through it.
14. Before making a key format length-uniform across parameter sets, check which suite-separation checks relied on length.
15. A key check value is not a MAC; document it as detecting relabelling and corruption only.
16. Any buffer that has held plaintext must be zeroizing before the first fallible call after the copy.
17. Check a component's parameter set against the designers' latest specification changelog, not only against the version the implementation claims.
18. A public key hashed into a binding must be canonical and in the prime-order subgroup (torsion-free and not the identity), not merely "not small-order".
19. Hash known-answer files from their git blobs (autocrlf off); a Windows checkout's CRLF conversion silently changes the bytes.
20. When a component's key and ciphertext lengths stay the same across an algorithm version change, length cannot reveal the mismatch and implicit rejection hides it; state which version a wire version means, or bump it.
21. A command-line lint gate also covers path-dependency workspace members; in-source allows there defeat it, so list them next to the gate.
22. Reproduce a KAT generator's RNG request boundaries exactly, not just its byte stream.
23. When official vectors use a key form the adapter does not store, drive upstream for that step and the adapter for the rest, and say so; do not widen the public API for tests.
24. A ported primitive is wired in only after it reproduces every official known-answer case; a partial port never ships.
25. A negative control must name any design known to be insecure even with sound components (for example XOR under chosen-ciphertext attack) and assert its expected break, rather than excluding it silently.
26. A binding or separation adversary must try every subset of components, not only all the breakable ones.
27. Run composition experiments through the library's own composition code and test byte-equality with the named suite before trusting any result.
28. Where a component signature scheme has no context input in its default mode, the composite must use a standardised variant that has one; a key-usage rule alone does not stop a standalone signing oracle on the same key.
29. When the only standardised context-bearing variant adds a prehash, state the new collision-resistance assumption and check that the other half still signs the unhashed representative.
30. Treat a component's context binding as a tested contract; a context-ignoring component silently removes separation.
31. When adding a suite family, check every pair of suites for equal object lengths, not only within a family.
32. Before relying on dependency optimisation for slow primitives, check whether the upstream code is generic over caller types; generic code compiles at the caller's optimisation level.
33. A bounded proof of a length-prefixed encoding must state the largest length it covers; truncating the prefix to the bits that bound needs survives the proof.
34. Record a proof as run only when its report exists; a harness that compiles is not a result.
35. A per-cell expected verdict must name its basis (claim, control or theory) and follow the project's claim, never the observed result.
36. Size a model-checking unwind bound from the longest object compared (including strings inside error values), not from the loop count.
37. When a model checker exhausts memory on symbolic lengths, enumerate concrete length shapes with symbolic contents; the union of the shapes must equal the stated bound and the list must be generated and checked.
38. Prove fixed-width length-prefix arithmetic over every length, separately from bounded content proofs.
39. A mutant counts as killed only when a property check fails, never when only an unwinding assertion fails.
