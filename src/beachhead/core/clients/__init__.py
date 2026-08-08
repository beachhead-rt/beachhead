"""Core clients: az and ado_search.

The only code that talks to ADO. Each client shares retry/throttle/scope/audit
behavior so modules don't reinvent it. See docs/api-clients.md.
"""
