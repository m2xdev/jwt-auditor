#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwt_auditor.py — defensive JWT audit tool.

Analyzes JWT tokens that YOU provide yourself (your own application's
tokens, your own secrets). Identifies known misconfigurations and
optionally checks whether your HMAC secret is weak (present in a
public wordlist).

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

DISCLAIMER
----------
This tool is intended ONLY for auditing tokens and secrets that belong to
you or that you are explicitly authorized to test. Do not use it against
systems or tokens you do not own. The author assumes no liability for
misuse. The weak-secret check is an OFFLINE operation performed locally on
your own machine, using your own wordlist, against your own token — it does
not perform any network requests and cannot be used to attack third parties
by itself.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# --- Logging: library-friendly NullHandler, opt-in configuration. ----------
logger = logging.getLogger("jwt_auditor")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------
def _b64url_decode(data: str) -> bytes:
    """Decode base64url without padding. Raises ValueError on bad input."""
    if not isinstance(data, str):
        raise ValueError("base64url input must be a string")
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url segment: {exc}") from exc


def _b64url_encode(raw: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_loads_loose(raw: bytes) -> Any:
    """Decode JSON segment, raising ValueError with context."""
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON segment could not be parsed: {exc}") from exc


# ---------------------------------------------------------------------------
# Public decode function
# ---------------------------------------------------------------------------
def decode_unverified(token: str) -> Dict[str, Any]:
    """
    Decode a JWT into its three parts WITHOUT verifying the signature.

    This is a public Base64url operation — no secret is required and no
    cryptographic check is performed. The signature is returned as raw
    bytes so callers can do their own validation.

    Returns:
        {
            "header": dict,
            "payload": dict,
            "signature": bytes,
            "signing_input": bytes,   # b"<header_b64>.<payload_b64>"
            "raw_segments": (header_b64, payload_b64, signature_b64),
        }
    """
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"JWT must have exactly 3 dot-separated segments, got {len(parts)}")
    header_b64, payload_b64, signature_b64 = parts
    header = _json_loads_loose(_b64url_decode(header_b64))
    payload = _json_loads_loose(_b64url_decode(payload_b64))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header and payload must be JSON objects")
    try:
        signature = _b64url_decode(signature_b64)
    except ValueError:
        signature = b""
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "signing_input": signing_input,
        "raw_segments": (header_b64, payload_b64, signature_b64),
    }


# ---------------------------------------------------------------------------
# Findings model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    code: str
    severity: str          # "info", "low", "medium", "high", "critical"
    title: str
    detail: str


@dataclass
class AuditReport:
    token_valid: bool
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, code: str, severity: str, title: str, detail: str) -> None:
        self.findings.append(Finding(code, severity, title, detail))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_valid": self.token_valid,
            "header": self.header,
            "payload": self.payload,
            "error": self.error,
            "findings": [asdict(f) for f in self.findings],
        }

    def pretty(self) -> str:
        lines = []
        lines.append("=== JWT Audit Report ===")
        lines.append(f"token_valid : {self.token_valid}")
        if self.error:
            lines.append(f"error       : {self.error}")
        lines.append(f"header      : {json.dumps(self.header, indent=2)}")
        lines.append(f"payload     : {json.dumps(self.payload, indent=2)}")
        lines.append(f"findings    : {len(self.findings)}")
        for f in self.findings:
            lines.append(f"  [{f.severity.upper():8}] {f.code}: {f.title}")
            lines.append(f"             {f.detail}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------
_KID_SUSPICIOUS = ("../", "..\\", ";", "|", "$(", "`", "\x00", "%2e%2e", "%00")
_ASYMMETRIC_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
                    "PS256", "PS384", "PS512", "EdDSA")


class JWTAuditor:
    """Audit a JWT you own for common misconfigurations."""

    def __init__(self, clock: Optional[int] = None):
        # Allow deterministic testing.
        self._now = clock if clock is not None else int(time.time())

    # ---- main entry point -------------------------------------------------
    def audit(self, token: str) -> AuditReport:
        try:
            decoded = decode_unverified(token)
        except ValueError as exc:
            return AuditReport(token_valid=False, error=str(exc))

        header = decoded["header"]
        payload = decoded["payload"]
        report = AuditReport(token_valid=True, header=header, payload=payload)

        self._check_alg_none(header, report)
        self._check_alg_confusion(header, report)
        self._check_exp(payload, report)
        self._check_iat_nbf(payload, report)
        self._check_kid(header, report)
        self._check_case(header, report)

        return report

    # ---- individual checks ------------------------------------------------
    def _check_alg_none(self, header: Dict[str, Any], report: AuditReport) -> None:
        alg = header.get("alg")
        if isinstance(alg, str) and alg.lower() == "none":
            report.add(
                "ALG_NONE",
                "critical",
                "'alg=none' accepted by token",
                "Token advertises no signature algorithm. If the server accepts "
                "such tokens, an attacker can forge any claims. Verify server-side "
                "that 'none' is rejected.",
            )

    def _check_alg_confusion(self, header: Dict[str, Any], report: AuditReport) -> None:
        alg = header.get("alg")
        if not isinstance(alg, str):
            return
        if alg.upper() == "HS256":
            # Heuristic: presence of asymmetric-oriented header fields, or a
            # signature length that fits HMAC but the surrounding hints point
            # to an asymmetric origin. Purely informational.
            hints = [k for k in ("jku", "jwks_uri", "x5u", "x5c") if k in header]
            if hints:
                report.add(
                    "ALG_CONFUSION_HINT",
                    "low",
                    "HS256 token with asymmetric header hints",
                    f"Header fields {hints} typically accompany RS/ES tokens. "
                    "If the same key material is trusted for both symmetric and "
                    "asymmetric verification, alg-confusion attacks become possible. "
                    "Confirm server-side that the key type is bound to the algorithm.",
                )

    def _check_exp(self, payload: Dict[str, Any], report: AuditReport) -> None:
        if "exp" not in payload:
            report.add(
                "NO_EXP",
                "high",
                "Token has no 'exp' claim",
                "Token never expires. Revocation must be handled elsewhere; "
                "a leaked token stays valid indefinitely.",
            )
            return
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            report.add(
                "EXP_BAD_TYPE",
                "medium",
                "'exp' claim has unexpected type",
                f"exp={exp!r} is not numeric. Servers may mishandle comparison.",
            )
            return
        if exp < self._now:
            report.add(
                "EXP_PAST",
                "medium",
                "Token already expired",
                f"exp={exp} is in the past (now={self._now}). If the server still "
                "accepts it, expiration is not enforced.",
            )

    def _check_iat_nbf(self, payload: Dict[str, Any], report: AuditReport) -> None:
        missing = [c for c in ("iat", "nbf") if c not in payload]
        if missing:
            report.add(
                "MISSING_TIME_CLAIMS",
                "info",
                "Missing time-based claims",
                f"Missing: {missing}. Not strictly required, but useful for "
                "replay-window control and token-age checks.",
            )

    def _check_kid(self, header: Dict[str, Any], report: AuditReport) -> None:
        kid = header.get("kid")
        if not isinstance(kid, str):
            return
        hit = next((pat for pat in _KID_SUSPICIOUS if pat in kid), None)
        if hit is not None:
            report.add(
                "KID_SUSPICIOUS",
                "high",
                "'kid' header contains suspicious characters",
                f"kid={kid!r} contains {hit!r}. If the server uses 'kid' to "
                "build file paths or SQL/commands, this may indicate path "
                "traversal or injection. Verify server-side sanitization.",
            )

    def _check_case(self, header: Dict[str, Any], report: AuditReport) -> None:
        alg = header.get("alg")
        typ = header.get("typ")
        # Heuristic: mixed-case algs like "Hs256" or "NONE" instead of the
        # canonical "HS256"/"none" suggest non-standard handling.
        if isinstance(alg, str) and alg not in ("none",) and alg != alg.upper():
            report.add(
                "ALG_NONCANONICAL_CASE",
                "low",
                "Non-canonical 'alg' casing",
                f"alg={alg!r} is not the canonical uppercase form. Servers that "
                "compare case-insensitively may accept unexpected values.",
            )
        if isinstance(typ, str) and typ != typ.upper() and typ.lower() != "jwt":
            report.add(
                "TYP_NONSTANDARD",
                "info",
                "Non-standard 'typ' value",
                f"typ={typ!r}. RFC 7519 recommends 'JWT'.",
            )

    # ---- weak secret check ------------------------------------------------
    def check_weak_secret(
        self,
        token: str,
        wordlist_path: str,
        max_attempts: int = 100000,
    ) -> Optional[str]:
        """
        Try to reproduce the HMAC signature of an HS256/HS384/HS512 token
        using candidates from a local wordlist.

        Purpose: verify whether YOUR OWN secret is predictable — e.g. run
        rockyou.txt or a top-10000 list against a token issued by your own
        application to see whether your secret is in a public corpus. This is
        an offline operation performed locally; it performs no network I/O
        and is not intended to compromise third-party tokens.

        Returns the matching secret as a string, or None.
        """
        decoded = decode_unverified(token)
        header = decoded["header"]
        alg = header.get("alg")
        if alg not in ("HS256", "HS384", "HS512"):
            raise ValueError(f"check_weak_secret only supports HS256/HS384/HS512, got {alg!r}")
        if not os.path.isfile(wordlist_path):
            raise FileNotFoundError(f"wordlist not found: {wordlist_path}")

        hash_ctor = {"HS256": hashlib.sha256,
                     "HS384": hashlib.sha384,
                     "HS512": hashlib.sha512}[alg]

        signing_input = decoded["signing_input"]
        expected_sig = decoded["signature"]
        attempts = 0
        with open(wordlist_path, "rb") as fh:
            for line in fh:
                if attempts >= max_attempts:
                    break
                attempts += 1
                candidate = line.rstrip(b"\r\n")
                if not candidate:
                    continue
                computed = hmac.new(candidate, signing_input, hash_ctor).digest()
                if hmac.compare_digest(computed, expected_sig):
                    logger.info("weak secret found after %d attempts", attempts)
                    try:
                        return candidate.decode("utf-8", errors="replace")
                    except Exception:
                        return candidate.hex()
        logger.info("no weak secret found in %d attempts", attempts)
        return None


# ---------------------------------------------------------------------------
# Self-test: generate synthetic tokens in-memory, no network.
# ---------------------------------------------------------------------------
def _make_token(header: Dict[str, Any], payload: Dict[str, Any],
                secret: Optional[bytes] = None) -> str:
    """Build a JWT with the given header/payload. Signs with secret if HS*."""
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    alg = header.get("alg", "none")
    if alg in ("HS256", "HS384", "HS512") and secret is not None:
        h = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret, signing_input, h).digest()
        s_b64 = _b64url_encode(sig)
    else:
        s_b64 = ""
    return f"{h_b64}.{p_b64}.{s_b64}"


def _run_self_test() -> int:
    """Run offline self-tests. Returns 0 on success, 1 on failure."""
    failures = 0

    def check(name: str, cond: bool) -> None:
        nonlocal failures
        status = "ok" if cond else "FAIL"
        print(f"  [{status}] {name}")
        if not cond:
            failures += 1

    now = 1_700_000_000
    auditor = JWTAuditor(clock=now)

    print("[self-test] decode_unverified")
    tok = _make_token({"alg": "HS256", "typ": "JWT"},
                      {"sub": "u1", "exp": now + 60}, b"secret")
    dec = decode_unverified(tok)
    check("header.alg == HS256", dec["header"]["alg"] == "HS256")
    check("payload.sub == u1", dec["payload"]["sub"] == "u1")
    check("signature non-empty", len(dec["signature"]) > 0)

    print("[self-test] alg=none detection")
    tok_none = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "x"})
    rep = auditor.audit(tok_none)
    check("ALG_NONE reported",
          any(f.code == "ALG_NONE" for f in rep.findings))

    print("[self-test] missing exp")
    tok_noexp = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, b"k")
    rep = auditor.audit(tok_noexp)
    check("NO_EXP reported",
          any(f.code == "NO_EXP" for f in rep.findings))

    print("[self-test] expired token")
    tok_exp = _make_token({"alg": "HS256", "typ": "JWT"},
                          {"sub": "x", "exp": now - 10}, b"k")
    rep = auditor.audit(tok_exp)
    check("EXP_PAST reported",
          any(f.code == "EXP_PAST" for f in rep.findings))

    print("[self-test] missing iat/nbf")
    rep = auditor.audit(tok_exp)
    check("MISSING_TIME_CLAIMS reported",
          any(f.code == "MISSING_TIME_CLAIMS" for f in rep.findings))

    print("[self-test] suspicious kid")
    tok_kid = _make_token({"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"},
                          {"sub": "x", "exp": now + 60, "iat": now, "nbf": now},
                          b"k")
    rep = auditor.audit(tok_kid)
    check("KID_SUSPICIOUS reported",
          any(f.code == "KID_SUSPICIOUS" for f in rep.findings))

    print("[self-test] non-canonical alg casing")
    tok_case = _make_token({"alg": "Hs256", "typ": "jwt"},
                           {"sub": "x", "exp": now + 60, "iat": now, "nbf": now},
                           b"k")
    rep = auditor.audit(tok_case)
    check("ALG_NONCANONICAL_CASE reported",
          any(f.code == "ALG_NONCANONICAL_CASE" for f in rep.findings))

    print("[self-test] alg confusion hint")
    tok_hint = _make_token(
        {"alg": "HS256", "typ": "JWT", "jku": "https://example/jwks.json"},
        {"sub": "x", "exp": now + 60, "iat": now, "nbf": now},
        b"k",
    )
    rep = auditor.audit(tok_hint)
    check("ALG_CONFUSION_HINT reported",
          any(f.code == "ALG_CONFUSION_HINT" for f in rep.findings))

    print("[self-test] weak secret detection (in-memory wordlist)")
    import tempfile
    secret = b"hunter2"
    tok_weak = _make_token({"alg": "HS256", "typ": "JWT"},
                           {"sub": "x", "exp": now + 60}, secret)
    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(b"password\n123456\nhunter2\nletmein\n")
        wl_path = tf.name
    try:
        found = auditor.check_weak_secret(tok_weak, wl_path)
        check("weak secret 'hunter2' found", found == "hunter2")
    finally:
        os.unlink(wl_path)

    print("[self-test] non-HS token rejected by check_weak_secret")
    tok_rs = _make_token({"alg": "RS256", "typ": "JWT"},
                         {"sub": "x", "exp": now + 60})
    try:
        auditor.check_weak_secret(tok_rs, "/dev/null")
        check("raises for RS256", False)
    except ValueError:
        check("raises for RS256", True)

    print()
    if failures:
        print(f"SELF-TEST FAILED: {failures} failure(s)")
        return 1
    print("SELF-TEST PASSED")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jwt_auditor",
        description="Audit a JWT that you own. Defensive use only.",
    )
    p.add_argument("--decode", metavar="TOKEN",
                   help="Decode a JWT and print header/payload (no verification).")
    p.add_argument("--audit", metavar="TOKEN",
                   help="Audit a JWT for known misconfigurations.")
    p.add_argument("--check-secret", metavar="TOKEN",
                   help="Check whether an HS* token's secret is in a wordlist (offline).")
    p.add_argument("--wordlist", metavar="PATH",
                   help="Path to wordlist for --check-secret.")
    p.add_argument("--max-attempts", type=int, default=100000,
                   help="Max wordlist entries to try for --check-secret.")
    p.add_argument("--self-test", action="store_true",
                   help="Run offline self-tests.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable logging to stderr.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s %(name)s: %(message)s")

    if args.self_test:
        return _run_self_test()

    if args.decode:
        try:
            dec = decode_unverified(args.decode)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "header": dec["header"],
            "payload": dec["payload"],
            "signature_b64": dec["raw_segments"][2],
            "signature_len_bytes": len(dec["signature"]),
        }, indent=2, ensure_ascii=False))
        return 0

    if args.audit:
        rep = JWTAuditor().audit(args.audit)
        print(rep.pretty())
        return 0 if rep.token_valid else 2

    if args.check_secret:
        if not args.wordlist:
            print("error: --check-secret requires --wordlist", file=sys.stderr)
            return 2
        try:
            found = JWTAuditor().check_weak_secret(
                args.check_secret, args.wordlist, args.max_attempts)
        except (ValueError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if found is None:
            print("no weak secret found in wordlist")
            return 0
        print(f"WEAK SECRET FOUND: {found!r}")
        return 1  # non-zero to signal "action required"

    _build_argparser().print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())