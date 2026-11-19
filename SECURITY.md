# Security Policy

## Project status

VYRA is a **research prototype**. It is a hybrid post-quantum cryptography
library at an early research stage.

- VYRA has **not** received independent cryptanalysis.
- VYRA has **not** received a third-party security audit.
- VYRA **must not** be used to protect real data, production systems, or any
  information whose confidentiality, integrity, or availability matters.

Do not rely on VYRA for any security guarantee.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue
or pull request for a security problem.

Use GitHub's private security advisory feature:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** to open a private security advisory.
3. Describe the issue, the affected code, and steps to reproduce it, if known.

Reports submitted this way are visible only to the maintainers and to you.
Please allow maintainers a reasonable opportunity to review and respond before
disclosing the issue publicly.

## Scope

Because VYRA is a research prototype, reports about design choices, missing
features, or known limitations are welcome as regular issues. Reports of
implementation flaws, memory-safety issues, incorrect cryptographic behavior,
or side-channel leakage should use the private advisory process above.
