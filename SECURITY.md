# Security Policy

## Supported Versions

We release security updates for the following versions of AKAGAMI:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

### For AKAGAMI Tool Issues

If you discover a security vulnerability in the AKAGAMI toolkit itself:

1. **DO NOT** open a public issue
2. Email us at: `security@akagami-toolkit.local` (or create a private GitHub issue)
3. Include detailed steps to reproduce
4. Provide your assessment of impact and severity

### For Vulnerabilities Found Using AKAGAMI

If you discover vulnerabilities in target systems while using AKAGAMI:

1. **Follow responsible disclosure practices**
2. Contact the affected organization's security team
3. Give them reasonable time to patch (typically 90 days)
4. Do not exploit or cause damage
5. Do not access sensitive data

## Security Best Practices

### When Using AKAGAMI

- ✅ **ONLY** test systems you own or have explicit written permission to test
- ✅ Use rate limiting and reasonable delays
- ✅ Respect robots.txt and access restrictions
- ✅ Document your testing authorization
- ✅ Report findings responsibly

### When Deploying AKAGAMI

- ✅ Use Docker containers for isolation
- ✅ Run with minimal privileges
- ✅ Keep dependencies updated
- ✅ Monitor logs for suspicious activity
- ✅ Use HTTPS in production

### Legal Compliance

- 📋 Obtain written authorization before testing
- 📋 Understand your local laws and regulations
- 📋 Follow industry standards (OWASP, NIST, etc.)
- 📋 Maintain detailed logs of testing activities
- 📋 Implement proper access controls

## What We Monitor

We monitor for:
- Malicious use patterns
- Unauthorized scanning activities
- Attempts to bypass security controls
- Suspicious API usage

## Response Timeline

- **Critical vulnerabilities**: 24-48 hours
- **High severity**: 1 week
- **Medium/Low severity**: 2-4 weeks

## Contact

For security-related concerns:
- Create a private issue on GitHub
- Use GitHub Security Advisories
- Contact project maintainers directly

## Legal Notice

AKAGAMI is intended for:
- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Vulnerability assessment of owned systems
- ✅ Compliance and audit activities

AKAGAMI is NOT intended for:
- ❌ Unauthorized access to systems
- ❌ Malicious activities or attacks
- ❌ Data theft or damage
- ❌ Harassment or illegal activities

**Users are solely responsible for compliance with applicable laws and regulations.**
