"""
Secrets stored in the database are encrypted with keys derived from
SECRET_KEY. A backup restored on a server with a different SECRET_KEY carries
the old key inside the (encrypted) backup; every stored secret is re-encrypted
under this server's key so scheduled jobs, SNMP polling, webhooks and the rest
keep working after the restore.
"""
import json
import logging
from typing import Callable, Dict, List, Optional, Tuple

from psycopg import sql

from app.core import credential_crypto as cc

logger = logging.getLogger(__name__)

ENC_PREFIX = "enc:v1:"

# (table, key column, secret column, purpose, row filter)
COLUMNS: List[Tuple[str, str, str, str, Optional[str]]] = [
    ("scheduled_jobs", "id", "params_encrypted", cc.PURPOSE_SCHEDULED_JOBS, None),
    ("asset_snmp_credentials", "id", "community_encrypted", cc.PURPOSE_NOC_SNMP, None),
    ("asset_snmp_credentials", "id", "auth_key_encrypted", cc.PURPOSE_NOC_SNMP, None),
    ("asset_snmp_credentials", "id", "priv_key_encrypted", cc.PURPOSE_NOC_SNMP, None),
    ("notification_webhooks", "id", "secret_encrypted", cc.PURPOSE_NOTIFICATIONS, None),
    ("cve_settings", "key", "value", cc.PURPOSE_CVE, "key IN ('nvd_api_key', 'signing_key')"),
    ("backup_destinations", "id", "secret_encrypted", cc.PURPOSE_SYSTEM_BACKUP, None),
]
# JSON settings rows: top-level string values carrying ENC_PREFIX.
JSON_COLUMNS = [("system_config_settings", "id", "config_json", cc.PURPOSE_SYSTEM_CONFIG)]


def _convert(value: str, purpose: str, old_key: str) -> Tuple[Optional[str], str]:
    """(new ciphertext or None, outcome). Values already under this server's
    key (rows carried over from the running system) are left alone."""
    try:
        plain = cc.decrypt(value, purpose, secret_key=old_key)
    except ValueError:
        try:
            cc.decrypt(value, purpose)
            return None, "current"
        except ValueError:
            return None, "unreadable"
    return cc.encrypt(plain, purpose), "rekeyed"


def _table_columns(cur, schema: str, table: str) -> set:
    cur.execute("""SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped""",
                (schema, table))
    return {r[0] for r in cur.fetchall()}


def rekey(cur, schema: str, old_key: str, check_only: bool = False) -> Dict[str, int]:
    """Re-encrypt every stored secret in `schema` from old_key to the current
    SECRET_KEY. check_only counts what would happen without writing."""
    totals = {"rekeyed": 0, "current": 0, "unreadable": 0}
    for table, pk, col, purpose, where in COLUMNS:
        if col not in _table_columns(cur, schema, table):
            continue
        q = sql.SQL("SELECT {}, {} FROM {}.{} WHERE {} IS NOT NULL").format(
            sql.Identifier(pk), sql.Identifier(col), sql.Identifier(schema), sql.Identifier(table),
            sql.Identifier(col))
        if where:
            q = q + sql.SQL(" AND " + where)
        cur.execute(q)
        for key, value in cur.fetchall():
            if not value:
                continue
            new, outcome = _convert(value, purpose, old_key)
            totals[outcome] += 1
            if new is not None and not check_only:
                cur.execute(sql.SQL("UPDATE {}.{} SET {} = %s WHERE {} = %s").format(
                    sql.Identifier(schema), sql.Identifier(table), sql.Identifier(col), sql.Identifier(pk)),
                    (new, key))
    for table, pk, col, purpose in JSON_COLUMNS:
        if col not in _table_columns(cur, schema, table):
            continue
        cur.execute(sql.SQL("SELECT {}, {} FROM {}.{}").format(
            sql.Identifier(pk), sql.Identifier(col), sql.Identifier(schema), sql.Identifier(table)))
        for key, payload in cur.fetchall():
            data = payload if isinstance(payload, dict) else json.loads(payload or "{}")
            changed = False
            for field, value in list(data.items()):
                if isinstance(value, str) and value.startswith(ENC_PREFIX):
                    new, outcome = _convert(value[len(ENC_PREFIX):], purpose, old_key)
                    totals[outcome] += 1
                    if new is not None:
                        data[field] = ENC_PREFIX + new
                        changed = True
            if changed and not check_only:
                cur.execute(sql.SQL("UPDATE {}.{} SET {} = %s WHERE {} = %s").format(
                    sql.Identifier(schema), sql.Identifier(table), sql.Identifier(col), sql.Identifier(pk)),
                    (json.dumps(data), key))
    if totals["unreadable"]:
        logger.warning("[sysbackup] %d stored secret(s) could not be opened with either key",
                       totals["unreadable"])
    return totals
