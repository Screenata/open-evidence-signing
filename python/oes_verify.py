#!/usr/bin/env python3
"""
oes_verify — single-file verifier for the Open Evidence Signing (OES) v1.0 format.

Verifies a signed evidence envelope (and, optionally, a v4.0 evidence-pack
manifest) without trusting the issuer. Mirrors the JavaScript reference
verifier; see SPEC.md for the protocol.

Usage:
  python3 oes_verify.py <envelope.oes.json | manifest.json> [options]

Options:
  --content <file>   raw evidence bytes for the content-hash check (spec §7.2)
  --keys <file>      discovery document (JSON) or a PEM file — the offline key source
  --offline          never touch the network; requires --keys
  --json             machine-readable output

Exit codes: 0 valid · 1 verification failed · 2 usage / I-O error

Requires the `cryptography` package (pip install cryptography).
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.request

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.exceptions import InvalidSignature
except ImportError:  # pragma: no cover
    sys.stderr.write("oes_verify requires the 'cryptography' package: pip install cryptography\n")
    sys.exit(2)

OES_CONTEXT = "https://openevidence.dev/signing/v1"
SUPPORTED = {"RSA-SHA256", "ECDSA-SHA256"}
SKEW = 5 * 60  # seconds


def canonicalize(value) -> bytes:
    """sorted-keys-2space canonical bytes (spec §4.2)."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")


def fingerprint(pem: str) -> str:
    # Spec §4.5: fingerprint is over the PEM with LF line endings. Normalize
    # CRLF so a key loaded from a CRLF file matches the issuer's fingerprint.
    return hashlib.sha256(pem.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:16]


def load_keys(keys_path, offline, envelope):
    """Return {fingerprint: key_entry}. key_entry has publicKeyPem/revoked/validTo."""
    if keys_path:
        raw = open(keys_path, "r", encoding="utf-8").read()
        if raw.lstrip().startswith("-----BEGIN"):
            return {fingerprint(raw): {"publicKeyPem": raw, "revoked": False, "validTo": None}}
        doc = json.loads(raw)
        return {k["fingerprint"]: k for k in doc.get("keys", [])}
    if offline:
        raise SystemExit("--offline requires --keys")
    url = (envelope or {}).get("issuer", {}).get("keyDiscovery")
    if not url:
        return {}
    if not url.startswith("https://"):
        raise SystemExit("refusing to fetch discovery over non-HTTPS URL")
    with urllib.request.urlopen(url) as r:  # noqa: S310
        doc = json.loads(r.read())
    return {k["fingerprint"]: k for k in doc.get("keys", [])}


def verify_signature(public_pem: str, signature_b64: str, message: bytes, algorithm: str) -> bool:
    key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    sig = base64.b64decode(signature_b64)
    try:
        if algorithm == "RSA-SHA256":
            key.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


def verify_envelope(envelope, evidence_bytes, keys):
    result = {"valid": False, "contentHashVerified": False, "checks": [], "errors": [], "warnings": [], "details": {}}

    if envelope.get("@context") != OES_CONTEXT:
        result["errors"].append("Unsupported @context")
        return result
    if envelope.get("version") != "1.0":
        result["errors"].append("Unsupported version")
        return result
    proof = envelope.get("proof", {})
    subject = envelope.get("subject", {})
    if not subject.get("contentHash", {}).get("value") or not proof.get("signatureValue"):
        result["errors"].append("Missing required fields")
        return result
    if proof.get("algorithm") not in SUPPORTED:
        result["errors"].append("Unsupported algorithm: %s" % proof.get("algorithm"))
        return result
    if proof.get("canonicalization") != "sorted-keys-2space":
        result["errors"].append("Unsupported canonicalization")
        return result
    if proof.get("signedFields") != "subject":
        result["errors"].append("Unsupported signedFields")
        return result

    if evidence_bytes is not None:
        actual = hashlib.sha256(evidence_bytes).hexdigest()
        if actual != subject["contentHash"]["value"]:
            result["errors"].append("Content hash mismatch")
            result["checks"].append({"name": "Content Hash", "passed": False})
            return result
        result["checks"].append({"name": "Content Hash", "passed": True})
        result["contentHashVerified"] = True
    else:
        result["warnings"].append("Evidence bytes not provided; content hash not verified")

    fp = proof["publicKeyFingerprint"]
    entry = keys.get(fp)
    if not entry:
        result["errors"].append("Signing key %s not found" % fp)
        return result
    if entry.get("revoked"):
        result["errors"].append("Signing key %s has been revoked" % fp)
        return result

    ok = verify_signature(entry["publicKeyPem"], proof["signatureValue"], canonicalize(subject), proof["algorithm"])
    result["checks"].append({"name": "Signature", "passed": ok})
    if not ok:
        result["errors"].append("Invalid signature")
        return result

    ts = proof.get("timestamp")
    if ts:
        # genTime sanity only; full RFC 3161 DER parsing is in the JS verifier.
        result["details"]["timestampedAt"] = ts.get("timestampedAt")
        result["warnings"].append("Timestamp present; messageImprint/DER not parsed by this verifier")
    else:
        result["warnings"].append("No TSA timestamp present")

    result["valid"] = True
    result["details"].update({"issuer": envelope.get("issuer", {}).get("id"), "keyFingerprint": fp, "algorithm": proof["algorithm"]})
    return result


def verify_manifest(manifest, keys):
    result = {"valid": False, "contentHashVerified": False, "checks": [], "errors": [], "warnings": [], "details": {}}
    if manifest.get("version") == "3.0":
        result["errors"].append("Manifest v3.0 is no longer supported; re-export")
        return result
    sig = manifest.get("cryptographic_signature")
    if not sig or not sig.get("signature"):
        result["errors"].append("Manifest has no cryptographic signature")
        return result
    if sig.get("algorithm") not in SUPPORTED:
        result["errors"].append("Unsupported algorithm")
        return result
    entry = keys.get(sig["publicKeyFingerprint"])
    if not entry:
        result["errors"].append("Signing key %s not found" % sig["publicKeyFingerprint"])
        return result
    body = {k: v for k, v in manifest.items() if k != "cryptographic_signature"}
    ok = verify_signature(entry["publicKeyPem"], sig["signature"], canonicalize(body), sig["algorithm"])
    result["checks"].append({"name": "Manifest Signature", "passed": ok})
    result["valid"] = ok
    if not ok:
        result["errors"].append("Manifest signature verification failed")
    return result


def main(argv):
    p = argparse.ArgumentParser(prog="oes_verify", add_help=True)
    p.add_argument("target")
    p.add_argument("--content")
    p.add_argument("--keys")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        with open(args.target, "r", encoding="utf-8") as f:
            parsed = json.load(f)
        content = open(args.content, "rb").read() if args.content else None
        keys = load_keys(args.keys, args.offline, parsed if "@context" in parsed else None)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("error: %s\n" % e)
        return 2

    if "@context" in parsed:
        result = verify_envelope(parsed, content, keys)
    elif "cryptographic_signature" in parsed or "version" in parsed:
        result = verify_manifest(parsed, keys)
    else:
        sys.stderr.write("Unrecognized artifact\n")
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n%s\n" % ("✓ VALID" if result["valid"] else "✗ INVALID"))
        for c in result["checks"]:
            print("  %s %s" % ("✓" if c["passed"] else "✗", c["name"]))
        for w in result["warnings"]:
            print("  ! %s" % w)
        for e in result["errors"]:
            sys.stderr.write("  error: %s\n" % e)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
