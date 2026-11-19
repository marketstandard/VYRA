## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

## How it was checked

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo xtask verify` (paste the summary line, and explain any gate that is not PASS)

## Checklist

- [ ] No `unsafe` code and no new cryptographic primitive or construction
- [ ] No test, assertion or expected result was weakened to make this pass
- [ ] Tests added or updated for changed behaviour
- [ ] Generated files regenerated if results changed (vectors, sizes, yield matrix, figures, paper data)
- [ ] `RULES.md` has a new one-line rule if this is a security-relevant fix
- [ ] `CHANGELOG.md` updated if a user of the library would notice
- [ ] Documentation claims nothing beyond what the evidence shows
