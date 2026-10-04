"""
Shared engine behind the benchmark modules added for wider device coverage
(Active Directory, DNS, DHCP, IIS, Docker, Kubernetes, MySQL, ESXi, Sophos).

The older modules (windows, linux, mssql, ...) each carry their own copy of the
same audit/hardening plumbing. The newer ones describe *what* they check — the
rules, the collection commands and the remediation templates — in a
``ModuleSpec`` and this package supplies the rest: the audit service, the
hardening executor and service, and the two routers. The endpoints, request
bodies and response shapes match the older modules exactly, so the frontend,
Harden All, scheduling, reports and remediation treat them the same way.
"""
