"""
MongoDB Audit Module

CIS compliance auditing for MongoDB database instances.
Follows the same modular pattern as the Cisco / Linux / Apache audit modules.
"""

from .router import router
from .service import MongoDBSHAuditService
from .mongo_client import MongoDBSSHClient, redact_sensitive_mongo_data
from .rules import (
    build_all_mongodb_cis_rules,
    evaluate_compliance,
    filter_rules_by_profile,
)

__all__ = [
    "router",
    "MongoDBSHAuditService",
    "MongoDBSSHClient",
    "redact_sensitive_mongo_data",
    "build_all_mongodb_cis_rules",
    "evaluate_compliance",
    "filter_rules_by_profile",
]
