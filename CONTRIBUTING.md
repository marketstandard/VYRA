# Contributing to VYRA

Thank you for your interest in VYRA. It is a research-stage project maintained
by [Market Standard, LLC](https://github.com/marketstandard), and outside
contributions are welcome: bug reports, new attacks, review of the
constructions, documentation fixes and code.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

You do not need to be a cryptographer to contribute. Roughly in order of how
much the project needs them:

- **Break something.** Add an attack to the failure-injection experiment
  (`crates/vyra-yield`) that wins where the matrix currently says "no attack
  found". This is the most valuable contribution the project can receive.
- **Review a construction.** Read [docs/SPEC.md](docs/SPEC.md) and
  [docs/SECURITY.md](docs/SECURITY.md) and open an issue for anything that is
  wrong, unclear, or claimed more strongly than the evidence supports.
- **Review the HQC port.** `crates/vyra-hqc` is new cryptographic code checked
  only against the official known-answer tests.
- **Measure.** Timing and side-channel behaviour have not been evaluated.
- **Report a bug or a documentation error.** Use the issue templates.
- **Improve the docs or the tooling.** Small fixes are welcome without an
  issue first.

For a larger change, open an issue before writing code so the approach can be
agreed first.

Security problems are reported privately: see [SECURITY.md](SECURITY.md).

## Getting set up

You need `git` and Rust installed with [rustup](https://rustup.rs). The
toolchain is selected by `rust-toolchain.toml`; no C compiler is needed.
[docs/BUILDING.md](docs/BUILDING.md) has the full platform notes.

```sh
git clone https://github.com/marketstandard/VYRA.git vyra
cd vyra
cargo build --workspace --locked
cargo test --workspace --locked
```

## Before opening a pull request

Run the checks below. CI runs the first three on every pull request (a few
minutes); the full `cargo xtask verify` runs weekly and before releases, so
please run it yourself for any change to code or results:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask verify
```

`cargo xtask verify` runs every gate in [docs/CHECKS.md](docs/CHECKS.md) and
takes about half an hour. While you iterate, `cargo xtask verify --quick` runs
a shorter pass; run the full one before you ask for review. If a gate fails for
a reason you cannot fix in the same change, say so in the pull request and
include the output.

Formatting follows the current stable `rustfmt`. If CI reports a formatting
difference you cannot reproduce, run `rustup update stable` and format again.

If your change alters a result, regenerate the files that depend on it and
commit them together with the change:

| You changed | Regenerate with |
|---|---|
| Wire formats, encodings or suites | `cargo xtask vectors` and `cargo xtask sizes` |
| The failure-injection experiment | `cargo run -p vyra-yield --release --bin yield-report -- --out results/` |
| Anything in `results/` | `python tools/figures/gen_figures.py` |
| Numbers quoted in the paper | `python paper/tools/gen_data.py`, then `python paper/tools/check_numbers.py` |

## Ground rules

- **No `unsafe` code.** Do not add `unsafe` blocks, functions, or traits.
- **No new cryptographic primitives.** Do not implement new primitives or
  invent new constructions. Changes must use existing, documented designs.
- **Never weaken a test to make it pass.** If a test fails, fix the code or
  explain in the pull request why the expectation itself is wrong.
- **Security-relevant fixes add a rule.** Every security-relevant fix must add
  a one-line rule to `RULES.md` that describes the invariant the fix protects.
- **Do not overstate.** Documentation and comments must not claim more than
  the evidence shows. A passing test is not a security argument, and "no
  attack found" is not "secure". Gate C1 rejects several such phrases.

## Pull requests

- Keep each pull request to one topic, and describe what changed and why.
- Add or update tests for any change in behaviour.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased" for anything
  a user of the library would notice.
- A maintainer reviews every pull request. CI must pass before merge.

## Licensing of contributions

VYRA is dual-licensed under the MIT License (`LICENSE-MIT`) and the Apache
License, Version 2.0 (`LICENSE-APACHE`). Unless you explicitly state otherwise,
any contribution you intentionally submit for inclusion in VYRA is licensed
under both of these licenses, without any additional terms or conditions.

By submitting a contribution, you confirm that you have the right to do so.
