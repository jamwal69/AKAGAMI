# Security Policy

AKAGAMI is intended for authorized security testing, bug bounty reconnaissance, and owned lab environments only. Do not use it against systems without explicit permission and current scope approval.

## Responsible Disclosure

If you believe you have found a security issue in AKAGAMI itself, please open a private GitHub security advisory if available, or use GitHub Issues with only non-sensitive reproduction details. Do not publish target data, credentials, tokens, customer information, or exploit material in a public issue.

## Sensitive Data

Do not commit `.env` files, API keys, credentials, session data, workspaces, scan output, reports, or logs that may contain secrets or target-specific information. Review generated artifacts before sharing them publicly.

## Safe Usage Expectations

- Confirm written authorization and scope before each engagement.
- Prefer passive and dry-run modes while validating configuration.
- Enable active scanning only when explicitly allowed by the target program.
- Treat findings as leads that require manual validation and responsible disclosure.
- Keep local tooling, dependencies, and API keys under your control.

## Bug Bounty Scope Reminder

Program scope can change. Re-check in-scope and out-of-scope assets before each mission, and stop immediately if AKAGAMI output points outside the authorized target set.
