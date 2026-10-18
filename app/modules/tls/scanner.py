"""
Reading the certificate of one TLS service: a TLS handshake and nothing else - no credentials, no request
after it. Network and parsing only; app/modules/tls/service.py decides what is scanned and stores it.

probe() makes up to four connections:
  1. a handshake that verifies the chain against the public authorities (certifi's bundle, through
     requests) and the organisation's own (OpenSSL's own path building, so appliance and internal CAs are
     judged as browsers judge them);
  2. if that is refused for the certificate, a handshake without verification, to read it anyway;
  3./4. if asked, one handshake each limited to TLS 1.0 and TLS 1.1, to see whether they are still
     accepted.
OpenSSL runs at security level 0 here so that old protocols, short keys and SHA-1 can be seen and
reported instead of making the handshake fail.
"""
import hashlib
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from requests.certs import where as public_authorities      # certifi's bundle, as requests uses it

TIMEOUT = 5.0

# OpenSSL verify codes (X509_V_ERR_*) that still mean the chain reached a trusted authority: path building
# succeeded and only a date check failed afterwards.
DATE_ONLY = {9, 10}            # not yet valid, expired
SELF_SIGNED = {18}             # the certificate signed itself
UNTRUSTED_ROOT = {19}          # the chain ends in a self-signed authority nobody here trusts
UNKNOWN_ISSUER = {2, 20, 21}   # the issuer is unknown (or missing from the chain the server sent)


class ProbeError(Exception):
    """The service could not be read: kind is "unreachable" (no connection) or "no_tls" (not a TLS
    service, or no protocol in common)."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass
class Probe:
    protocol: Optional[str] = None
    chain: List[bytes] = field(default_factory=list)       # DER, leaf first, as the server sent it
    trusted: Optional[bool] = None
    self_signed: bool = False
    trust_error: Optional[str] = None
    old_protocols: Optional[List[str]] = None


def _context(verify: bool, cadata: Optional[str] = None, only=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)     # TLSv1 / TLSv1_1 are what is looked for
        if only is not None:
            ctx.minimum_version = ctx.maximum_version = only
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=public_authorities())
        if cadata:
            ctx.load_verify_locations(cadata=cadata)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _der(cert) -> bytes:
    """A certificate of get_unverified_chain(): DER bytes, or an object that gives them."""
    return cert if isinstance(cert, (bytes, bytearray)) else cert.public_bytes(ssl.Encoding.DER)


def _handshake(ctx: ssl.SSLContext, host: str, port: int, server_name: Optional[str], timeout: float):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, ValueError) as e:
        raise ProbeError("unreachable", str(e) or type(e).__name__)
    try:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=server_name or None) as tls:
            return tls.version(), [_der(c) for c in tls.get_unverified_chain() or []]
    finally:
        sock.close()


def probe(host: str, port: int, server_name: Optional[str] = None, cadata: Optional[str] = None,
          check_protocols: bool = True, timeout: float = TIMEOUT) -> Probe:
    out = Probe()
    try:
        out.protocol, out.chain = _handshake(_context(True, cadata), host, port, server_name, timeout)
        out.trusted = True
    except ssl.SSLCertVerificationError as e:
        code = e.verify_code
        out.trusted = code in DATE_ONLY
        out.self_signed = code in SELF_SIGNED
        out.trust_error = None if out.trusted else (e.verify_message or str(e))[:200]
        try:
            out.protocol, out.chain = _handshake(_context(False), host, port, server_name, timeout)
        except ssl.SSLError as e2:
            raise ProbeError("no_tls", str(e2)[:300])
        except OSError as e2:
            raise ProbeError("unreachable", str(e2) or type(e2).__name__)
    except ssl.SSLError as e:       # an OSError too: before it
        raise ProbeError("no_tls", str(e)[:300])
    except OSError as e:            # reset or timed out during the handshake
        raise ProbeError("unreachable", str(e) or type(e).__name__)
    if not out.chain:
        raise ProbeError("no_tls", "no certificate")
    if check_protocols:
        out.old_protocols = []
        for version, label in ((ssl.TLSVersion.TLSv1, "TLSv1"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
            if out.protocol == label:
                out.old_protocols.append(label)
                continue
            try:
                _handshake(_context(False, only=version), host, port, server_name, timeout)
                out.old_protocols.append(label)
            except (ProbeError, ssl.SSLError, OSError):
                pass
    return out


# ── the certificate ──────────────────────────────────────────────────────

def _utc(d: datetime) -> datetime:
    return d.astimezone(timezone.utc).replace(tzinfo=None)


def key_of(cert: x509.Certificate) -> Dict:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"key_type": "RSA", "key_bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"key_type": "EC", "key_bits": key.curve.key_size}
    if isinstance(key, dsa.DSAPublicKey):
        return {"key_type": "DSA", "key_bits": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"key_type": "Ed25519", "key_bits": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"key_type": "Ed448", "key_bits": 456}
    return {"key_type": None, "key_bits": None}


def names_of(cert: x509.Certificate) -> List[str]:
    """The names a certificate is for: its subjectAltName DNS names and addresses, else its common name."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
        names += [str(a) for a in san.get_values_for_type(x509.IPAddress)]
        if names:
            return names
    except x509.ExtensionNotFound:
        pass
    cn = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    return [str(v).lower() for v in cn[:1]]


def describe(der: bytes) -> Dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        sig = cert.signature_hash_algorithm
        signature = sig.name if sig is not None else None
    except Exception:       # e.g. RSASSA-PSS or a hash cryptography does not know
        signature = None
    return {
        "subject": cert.subject.rfc4514_string()[:500],
        "issuer": cert.issuer.rfc4514_string()[:500],
        "names": names_of(cert)[:100],
        "serial": format(cert.serial_number, "x")[:80],
        "fingerprint": hashlib.sha256(der).hexdigest(),
        "not_before": _utc(cert.not_valid_before_utc),
        "not_after": _utc(cert.not_valid_after_utc),
        "signature": signature,
        "self_issued": cert.subject == cert.issuer,
        **key_of(cert),
    }


def chain_summary(chain: List[bytes]) -> List[Dict]:
    out = []
    for der in chain[:8]:
        try:
            c = x509.load_der_x509_certificate(der)
            out.append({"subject": c.subject.rfc4514_string()[:300], "issuer": c.issuer.rfc4514_string()[:300],
                        "not_after": _utc(c.not_valid_after_utc).isoformat()})
        except ValueError:
            out.append({"subject": "?", "issuer": "?", "not_after": None})
    return out


def parse_ca(pem: str) -> Dict:
    """An authority the organisation uploads: one PEM certificate that may sign others."""
    try:
        cert = x509.load_pem_x509_certificate(pem.strip().encode())
    except ValueError:
        raise ValueError("The file is not a PEM certificate")
    try:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("This certificate is not a certificate authority")
    except x509.ExtensionNotFound:
        pass    # old self-made roots often lack it; OpenSSL still accepts a self-signed v1 root
    from cryptography.hazmat.primitives.serialization import Encoding
    der = cert.public_bytes(Encoding.DER)
    return {"subject": cert.subject.rfc4514_string()[:500], "fingerprint": hashlib.sha256(der).hexdigest(),
            "not_after": _utc(cert.not_valid_after_utc), "pem": cert.public_bytes(Encoding.PEM).decode()}
