# jwt-auditor

A defensive JWT audit tool for Python — decodes tokens, flags known
misconfigurations, and can check whether an HS256/384/512 secret is weak
against a local wordlist. Pure standard library, no PyJWT dependency.

## What this is

Analyzes JWT tokens that **you provide yourself** — your own application's
tokens, your own secrets. It does not fetch, intercept, or guess tokens
belonging to anyone else.

### What it checks

| Finding | Severity | What it means |
|---|---|---|
| `ALG_NONE` | critical | `alg: none` — if the server accepts this, anyone can forge claims |
| `ALG_CONFUSION_HINT` | low | HS256 token with RS/ES-style header hints (`jku`, `x5u`, etc.) |
| `NO_EXP` | high | No expiration claim — token never expires |
| `EXP_PAST` | medium | Token's `exp` is already in the past |
| `EXP_BAD_TYPE` | medium | `exp` is present but not numeric |
| `MISSING_TIME_CLAIMS` | info | Missing `iat`/`nbf` |
| `KID_SUSPICIOUS` | high | `kid` header contains `../`, `;`, `` ` ``, etc. — possible path traversal/injection if the server uses `kid` to look up keys |
| `ALG_NONCANONICAL_CASE` | low | Non-canonical casing in `alg` (e.g. `Hs256` instead of `HS256`) |
| `TYP_NONSTANDARD` | info | `typ` isn't the RFC 7519-recommended `JWT` |

## Installation

```bash
git clone https://github.com/m2xdev/jwt-auditor
cd jwt-auditor
```

No dependencies — pure standard library (`base64`, `json`, `hmac`,
`hashlib`). Just run with Python 3.

## Usage

```bash
# Decode a token without verifying the signature
python jwt_auditor.py --decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Full audit — header/payload + misconfiguration findings
python jwt_auditor.py --audit eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Check if your own HS256/384/512 secret is weak, offline
python jwt_auditor.py --check-secret <your-token> --wordlist rockyou.txt

# Offline self-test
python jwt_auditor.py --self-test
```

### Weak secret check

```bash
python jwt_auditor.py --check-secret <token> --wordlist top-10000-passwords.txt --max-attempts 10000
```

This is an **offline** operation: it computes HMAC locally against each
wordlist entry and compares it to the token's signature using a
constant-time comparison. No network requests are made. Use it to verify
that the secret **you** chose for **your** application isn't predictable —
not to attack tokens you don't own.

Exit code `1` means a weak secret was found (treat as "action required" in
scripts/CI); `0` means the wordlist didn't contain the secret.

## Using as a library

```python
from jwt_auditor import decode_unverified, JWTAuditor

decoded = decode_unverified(token)
print(decoded["header"], decoded["payload"])

report = JWTAuditor().audit(token)
for finding in report.findings:
    print(finding.severity, finding.code, finding.title)
```

## Running self-tests

```bash
python jwt_auditor.py --self-test
```

11 offline tests — synthetic tokens generated in-memory, no network calls.
Covers every misconfiguration check plus the weak-secret finder (positive
and negative cases).

## ⚠️ Disclaimer

This tool is intended only for auditing tokens and secrets that belong to
you, or that you are explicitly authorized to test. Do not use it against
systems or tokens you do not own.

The weak-secret check is an **offline** operation performed locally on
your own machine, using your own wordlist, against your own token — it
performs no network requests and is not, by itself, a tool for
compromising third-party tokens.

The software is provided **"AS IS"**, without warranty of any kind,
express or implied. By using this code, you are solely responsible for
its use. The author is not liable for any damages arising from the use of
this software.

## Related projects

- [csrf-shield](https://github.com/m2xdev/csrf-shield) / [csrf-lab](https://github.com/m2xdev/csrf-lab)
- [rate-limit-shield](https://github.com/m2xdev/rate-limit-shield)
- [ssrf-shield](https://github.com/m2xdev/ssrf-shield) / [ssrf-lab](https://github.com/m2xdev/ssrf-lab)
- [nosql-shield](https://github.com/m2xdev/nosql-shield) / [nosql-lab](https://github.com/m2xdev/nosql-lab)
- [xss-shield](https://github.com/m2xdev/xss-shield) / [xss-lab](https://github.com/m2xdev/xss-lab)
- [query-sql](https://github.com/m2xdev/query-sql) / [query-lab](https://github.com/m2xdev/query-lab)