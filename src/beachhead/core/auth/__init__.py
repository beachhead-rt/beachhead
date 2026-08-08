"""core/auth — credential ownership for Beachhead.

Slice 1: audience classification + read-only token store.
Slice 2: ``TokenEntry`` + ``AuthBroker`` with async ``get()`` + refresh.
Slice 3: ``acquire_token_az_context``.
Slice 4: ``token_cache`` — file-based persistence for cross-command use.

core/auth is the sole owner of credentials; modules and clients never
re-implement auth.
"""

from beachhead.core.auth.ado_pat import acquire_token_ado_pat
from beachhead.core.auth.audience import Audience, classify_audience
from beachhead.core.auth.az_context import acquire_token_az_context
from beachhead.core.auth.broker import AuthBroker, MsalRefresher, Refresher
from beachhead.core.auth.token_cache import default_cache_path, load_tokens, save_tokens
from beachhead.core.auth.token_entry import TokenEntry

__all__ = [
    "Audience",
    "AuthBroker",
    "MsalRefresher",
    "Refresher",
    "TokenEntry",
    "acquire_token_ado_pat",
    "acquire_token_az_context",
    "classify_audience",
    "default_cache_path",
    "load_tokens",
    "save_tokens",
]
