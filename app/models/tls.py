"""
TLS certificates of the services the assets run (app/modules/tls): what each TLS port presents, checked
for expiry, trust, name, key and signature strength, and old protocol versions.

  TlsEndpoint    one TLS service of an asset (address and port) with the certificate it presented at the
                 last scan; "auto" ones come from the scan of the usual TLS ports and the open ports
                 discovery saw, "manual" ones were added by hand. The problems are not stored: they are
                 judged from these fields and today's date when read (app/modules/tls/checks.py)
  TlsTrustedCa   a certificate authority of the organisation: certificates it issued count as trusted,
                 besides the public authorities NGCorion trusts
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from app.core.database import Base

SOURCE_AUTO = "auto"
SOURCE_MANUAL = "manual"


class TlsEndpoint(Base):
    __tablename__ = "tls_endpoints"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    host = Column(String(255), nullable=False)                     # address connected to
    port = Column(Integer, nullable=False)
    server_name = Column(String(255), nullable=True)               # name sent (SNI) and checked, if any
    source = Column(String(10), nullable=False, default=SOURCE_AUTO)
    enabled = Column(Boolean, nullable=False, default=True)        # off: not scanned, no findings
    status = Column(String(12), nullable=False, default="pending") # pending | read | unreachable | no_tls
    error = Column(String(300), nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    last_ok_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    # the certificate at the last successful scan
    subject = Column(String(500), nullable=True)
    issuer = Column(String(500), nullable=True)
    names = Column(JSON, nullable=True)                            # subjectAltName DNS names and addresses
    serial = Column(String(80), nullable=True)
    fingerprint = Column(String(64), nullable=True)                # SHA-256, hex
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    key_type = Column(String(10), nullable=True)                   # RSA | EC | DSA | Ed25519 | Ed448
    key_bits = Column(Integer, nullable=True)
    signature = Column(String(20), nullable=True)                  # hash of the signature: sha256, sha1 ...
    self_signed = Column(Boolean, nullable=True)
    trusted = Column(Boolean, nullable=True)
    trust_error = Column(String(200), nullable=True)
    protocol = Column(String(10), nullable=True)                   # negotiated: TLSv1.3 ...
    old_protocols = Column(JSON, nullable=True)                    # accepted of TLSv1, TLSv1.1; None: not checked
    chain = Column(JSON, nullable=True)                            # [{subject, issuer, not_after}]
    cert_changed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    __table_args__ = (UniqueConstraint("asset_id", "host", "port", name="uq_tls_endpoints_asset_host_port"),)


class TlsTrustedCa(Base):
    __tablename__ = "tls_trusted_cas"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    subject = Column(String(500), nullable=False)
    fingerprint = Column(String(64), nullable=False, unique=True)
    pem = Column(Text, nullable=False)
    not_after = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
