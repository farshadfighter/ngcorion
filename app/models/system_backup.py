"""
NGCorion self-backup (app/modules/sysbackup): backups of the product itself -
its database and the files it keeps on disk - not of the network devices
(those are DeviceBackup, app/models/backup.py).

SystemBackup       one .ngbak archive in BACKUP_DIR, with where copies were
                   sent and when it was last checked.
BackupDestination  an SFTP server or Windows share that receives a copy of
                   every backup.
SystemRestore      a restore of a backup onto this server, or the weekly
                   restore test that loads a backup into a scratch schema.

These tables describe this server's disk, so a restore keeps them from the
running system rather than taking them from the backup. For the same reason
they hold no foreign key to users: the users of a restored backup are not
the users the catalog was written by.
"""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from app.core.database import Base

# SystemBackup.kind
KIND_SCHEDULED = "scheduled"
KIND_MANUAL = "manual"
KIND_SAFETY = "safety"            # taken automatically right before a restore
KIND_UPLOADED = "uploaded"        # brought in from another server or an older copy
KINDS = (KIND_SCHEDULED, KIND_MANUAL, KIND_SAFETY, KIND_UPLOADED)

# SystemBackup.status
BK_QUEUED = "queued"
BK_RUNNING = "running"
BK_READY = "ready"
BK_FAILED = "failed"
BK_MISSING = "missing"            # the file is gone from BACKUP_DIR
BK_PENDING = (BK_QUEUED, BK_RUNNING)

# Optional parts of a backup. "essential" is always there.
CONTENTS = ("essential", "reports", "cve", "noc_history")

# SystemRestore.kind / status
RESTORE = "restore"
RESTORE_TEST = "test"
RS_QUEUED = "queued"
RS_RUNNING = "running"
RS_SUCCEEDED = "succeeded"
RS_FAILED = "failed"
RS_PENDING = (RS_QUEUED, RS_RUNNING)

DEST_TYPES = ("sftp", "smb")


class SystemBackup(Base):
    __tablename__ = "system_backups"

    id = Column(Integer, primary_key=True)
    kind = Column(String(12), nullable=False, default=KIND_MANUAL, index=True)
    tier = Column(String(8), nullable=True)                 # daily | weekly | monthly (scheduled)
    status = Column(String(10), nullable=False, default=BK_QUEUED, index=True)
    step = Column(String(40), nullable=True)
    progress = Column(Integer, nullable=False, default=0)
    contents = Column(JSON, nullable=False, default=list)
    filename = Column(String(200), nullable=True, unique=True)
    size_bytes = Column(BigInteger, nullable=True)
    sha256 = Column(String(64), nullable=True)
    app_version = Column(String(20), nullable=True)
    db_revision = Column(String(40), nullable=True)
    key_id = Column(String(40), nullable=True)               # which passphrase opens it
    source_host = Column(String(120), nullable=True)
    summary = Column(JSON, nullable=True)                    # tables, rows, files, per-part sizes
    destinations = Column(JSON, nullable=False, default=list)   # [{id, name, status, error, at, path}]
    targets = Column(JSON, nullable=True)                    # destination ids picked for a manual backup; None = all
    verified_at = Column(DateTime, nullable=True)
    verify_status = Column(String(10), nullable=True)        # ok | failed
    verify_error = Column(Text, nullable=True)
    tested_at = Column(DateTime, nullable=True)
    test_status = Column(String(10), nullable=True)          # ok | failed
    note = Column(String(300), nullable=True)
    error = Column(Text, nullable=True)
    runner = Column(String(120), nullable=True)
    created_by = Column(Integer, nullable=True)
    created_by_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


class BackupDestination(Base):
    __tablename__ = "backup_destinations"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    type = Column(String(8), nullable=False)                 # sftp | smb
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=True)
    username = Column(String(255), nullable=True)
    domain = Column(String(120), nullable=True)              # smb
    share = Column(String(255), nullable=True)               # smb
    path = Column(String(500), nullable=True)                # folder on the server / in the share
    auth = Column(String(10), nullable=False, default="password")    # password | key (sftp)
    secret_encrypted = Column(Text, nullable=True)           # password or private key
    host_key = Column(Text, nullable=True)                   # sftp: pinned on first contact
    enabled = Column(Boolean, nullable=False, default=True)
    last_status = Column(String(10), nullable=True)          # ok | failed
    last_error = Column(Text, nullable=True)
    last_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class SystemRestore(Base):
    __tablename__ = "system_restores"

    id = Column(Integer, primary_key=True)
    kind = Column(String(8), nullable=False, default=RESTORE, index=True)
    backup_id = Column(Integer, ForeignKey("system_backups.id", ondelete="SET NULL"), nullable=True, index=True)
    backup_label = Column(String(200), nullable=True)        # kept when the backup is deleted later
    status = Column(String(10), nullable=False, default=RS_QUEUED, index=True)
    step = Column(String(40), nullable=True)
    progress = Column(Integer, nullable=False, default=0)
    steps = Column(JSON, nullable=False, default=list)       # [{key, status, at, detail}]
    safety_backup_id = Column(Integer, ForeignKey("system_backups.id", ondelete="SET NULL"), nullable=True)
    result = Column(JSON, nullable=True)                     # rows, re-keyed secrets, carried-over data
    error = Column(Text, nullable=True)
    runner = Column(String(120), nullable=True)
    requested_by = Column(Integer, nullable=True)
    requested_by_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
