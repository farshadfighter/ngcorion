"""
How much disk the live rows of a table take - what a storage budget is about.

pg_total_relation_size is the size of a table's files. A DELETE frees space inside them for new rows but
does not shrink them (only VACUUM FULL does, and it locks the table), so the files of a table that once
reached its storage budget stay at that size however much is deleted. A budget checked against the file
size then deleted again on every run (syslog: a fifth of the messages; NOC metrics: up to a million
samples) until little history was left. This estimates the live rows' share of the files from their
count and average size, and charges them that share of the whole footprint (indexes and TOAST included).
"""
from typing import Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

TABLES = {"syslog_messages", "asset_metric_samples", "asset_metric_rollups"}
TUPLE_OVERHEAD = 28          # tuple header (24 aligned) + line pointer (4)
SAMPLE = 1000                # newest rows whose average size stands for all


def live_bytes(db: Session, table: str) -> Tuple[int, int]:
    """(bytes the live rows take with their share of indexes and TOAST, number of live rows)."""
    if table not in TABLES:                     # a name goes into SQL below: only the known tables
        raise ValueError(f"unknown table {table}")
    files, heap = db.execute(text(
        f"SELECT pg_total_relation_size('{table}'), pg_relation_size('{table}')")).one()  # nosec B608
    rows = int(db.execute(text(f"SELECT count(*) FROM {table}")).scalar() or 0)  # nosec B608
    if not rows or not heap:
        return (int(files or 0) if rows else 0), rows
    avg = db.execute(text(
        f"SELECT avg(pg_column_size(t.*)) FROM (SELECT * FROM {table} ORDER BY id DESC LIMIT {SAMPLE}) t"  # nosec B608
    )).scalar() or 0
    share = min(1.0, rows * (float(avg) + TUPLE_OVERHEAD) / heap)
    return int(files * share), rows
