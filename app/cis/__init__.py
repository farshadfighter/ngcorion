"""
Self-contained CIS benchmark subsystem.

This package hosts stand-alone CIS Benchmark auditing/hardening services that
run over SSH and return plain ``list[CISResult]`` objects (see
:mod:`app.cis.base`). It is intentionally decoupled from the DB-backed
``app.modules.*`` audit pipeline so a benchmark can be driven directly.
"""
