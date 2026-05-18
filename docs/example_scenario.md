# Synthetic Akagami Scenario

This is a documentation-only scenario. It does not describe a real target, real program, real scan, real account, real vulnerability, or historical engagement result.

## Target

- Program: Synthetic Program
- Scope: `*.sandbox-target.test`, `api.sandbox-target.test`, `198.51.100.0/24`
- Out of scope: `payments.sandbox-target.test`, `production.sandbox-target.test`
- Default mode: passive-first, active scans disabled until explicitly authorized

## Intended Workflow

1. Start with `config/example_bug_bounty.yaml`.
2. Confirm the written authorization and scope boundaries.
3. Run passive recon first.
4. Review stored intel and endpoint inventory.
5. Enable active scanning only after confirming the rules of engagement.
6. Treat scanner output as leads, not confirmed vulnerabilities.
7. Manually validate any finding before writing a report.

## Example Report Notes

Use placeholder language until a finding is reproduced:

- "Potential exposed administrative path observed; manual validation required."
- "Scanner reported a candidate CVE; version and exploitability are unconfirmed."
- "Endpoint appears high-signal because of path and parameter names; no impact proven."

Do not publish real program names, production domains, customer data, credentials, or historical testing results in example scenarios.
