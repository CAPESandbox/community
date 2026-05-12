import re
from lib.cuckoo.common.abstracts import Signature


def _get_pe(results):
    return (results.get("target") or {}).get("file", {}).get("pe", {})


KNOWN_CA_TERMS = (
    "digicert", "entrust", "comodo", "sectigo", "verisign",
    "globalsign", "usertrust", "thawte", "geotrust", "amazon",
    "microsoft", "google", "apple", "root ca", "root authority",
    "symantec", "godaddy", "rapidssl", "network solutions", "ssl.com",
)

DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9\-\.]+\.(nl|com|net|org|ru|cn|de|io|co|info|biz|xyz|top|site)$', re.I)


def _is_known_ca(name):
    if not name:
        return False
    nl = name.lower()
    return any(t in nl for t in KNOWN_CA_TERMS)


class PECertSelfSigned(Signature):
    name = "pe_cert_self_signed"
    description = "PE is signed with a self-signed certificate (no trusted CA chain)"
    severity = 3
    weight = 3
    confidence = 80
    categories = ["static", "evasion"]
    authors = ["wmetcalf"]
    minimum = "1.2"
    ttps = ["T1553.002"]
    evented = False

    def run(self):
        pe = _get_pe(self.results)
        ds = pe.get("digital_signers") or []
        gs = pe.get("guest_signers") or {}

        for cert in ds:
            subject = cert.get("subject_commonName", "")
            issuer = cert.get("issuer_commonName", "")
            if not subject or not issuer:
                continue
            if subject.lower() != issuer.lower():
                continue
            if _is_known_ca(subject):
                continue
            self.data.append({
                "subject": subject,
                "sha1": cert.get("sha1_fingerprint", ""),
                "not_after": cert.get("not_after", ""),
            })

        if not self.data:
            for signer in gs.get("aux_signers") or []:
                if "Certificate Chain" not in (signer.get("name") or ""):
                    continue
                issued_to = signer.get("Issued to", "")
                issued_by = signer.get("Issued by", "")
                if issued_to and issued_to == issued_by and not _is_known_ca(issued_to):
                    self.data.append({
                        "subject": issued_to,
                        "sha1": signer.get("SHA1 hash", ""),
                        "expires": signer.get("Expires", ""),
                    })

        return bool(self.data)


class PECertSuspiciousIssuer(Signature):
    name = "pe_cert_suspicious_issuer"
    description = (
        "PE signed by an unrecognized CA with a short validity window or domain-style subject — "
        "consistent with certificates purchased from low-trust or compromised issuers"
    )
    severity = 3
    weight = 3
    confidence = 75
    categories = ["static", "evasion"]
    authors = ["wmetcalf"]
    minimum = "1.2"
    ttps = ["T1553.002"]
    evented = False

    def run(self):
        pe = _get_pe(self.results)
        ds = pe.get("digital_signers") or []
        gs = pe.get("guest_signers") or {}

        # Only one cert in chain = no intermediate CA, incomplete chain
        chain_certs = [s for s in (gs.get("aux_signers") or [])
                       if "Certificate Chain" in (s.get("name") or "")]
        single_cert_chain = len(chain_certs) == 1

        for cert in ds:
            subject = cert.get("subject_commonName", "")
            issuer = cert.get("issuer_commonName", "")
            if not subject or not issuer:
                continue
            if subject.lower() == issuer.lower():
                continue  # handled by pe_cert_self_signed
            if _is_known_ca(issuer):
                continue

            suspicious = False
            reasons = []

            if single_cert_chain:
                suspicious = True
                reasons.append("single-cert chain (no intermediate CA)")

            # Domain name as code-signing subject
            if DOMAIN_RE.match(subject):
                suspicious = True
                reasons.append(f"domain-style subject CN: {subject}")

            # Very short validity (< 180 days)
            try:
                from datetime import datetime
                nb = datetime.fromisoformat(cert.get("not_before", "").replace("Z", ""))
                na = datetime.fromisoformat(cert.get("not_after", "").replace("Z", ""))
                days = (na - nb).days
                if days < 180:
                    suspicious = True
                    reasons.append(f"short validity: {days} days")
            except Exception:
                pass

            if suspicious:
                self.data.append({
                    "subject": subject,
                    "issuer": issuer,
                    "sha1": cert.get("sha1_fingerprint", ""),
                    "reasons": ", ".join(reasons),
                })

        return bool(self.data)


class PECertInvalidSignature(Signature):
    name = "pe_cert_invalid_signature"
    description = "PE Authenticode signature failed cryptographic verification (tampered, revoked, or unresolvable chain)"
    severity = 4
    weight = 4
    confidence = 85
    categories = ["static", "evasion"]
    authors = ["wmetcalf"]
    minimum = "1.2"
    ttps = ["T1553.002", "T1036"]
    evented = False

    BAD_ERRORS = (
        "did not verify",
        "revoked",
        "chain could not be built",      # 0x800B010A
        "0x800b010a",
        "0x800b0109",                     # revoked
        "0x80096010",                     # hash mismatch
        "0x800b0101",                     # expired
    )

    def run(self):
        pe = _get_pe(self.results)
        gs = pe.get("guest_signers") or {}

        if not gs or gs.get("aux_valid"):
            return False
        err = (gs.get("aux_error_desc") or "").lower()
        if not err or "no signature" in err:
            return False
        if not any(t in err for t in self.BAD_ERRORS):
            return False

        signers = gs.get("aux_signers") or []
        leaf = next(
            (s for s in signers if "Certificate Chain" in (s.get("name") or "")),
            {}
        )
        self.data.append({
            "error": gs.get("aux_error_desc", ""),
            "signer": leaf.get("Issued to", "unknown"),
            "issuer": leaf.get("Issued by", "unknown"),
            "sha1": gs.get("aux_sha1") or leaf.get("SHA1 hash", ""),
        })
        return True
