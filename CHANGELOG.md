# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial implementation.
- Figures for the README and the paper, drawn from `results/` by `tools/figures/gen_figures.py`.
- Community files: code of conduct, issue and pull request templates, `CODEOWNERS`, `CITATION.cff`, `SUPPORT.md`, `NOTICE`.

### Changed

- The copyright holder is Market Standard, LLC; the repository is `marketstandard/VYRA`.
- CI is split: a fast check (format, lints, tests; about 7 minutes) on every pull request and push to `main`, and the full gate run weekly and on demand.
- `results/verification-report.*` no longer records machine-specific absolute paths; they are written as `<repo>`, `<tmp>` and `<home>`.
