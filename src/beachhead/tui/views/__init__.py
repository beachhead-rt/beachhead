"""TUI view widgets."""

from beachhead.tui.views.dashboard import DashboardView
from beachhead.tui.views.detail import (
    AttackPathDetailScreen,
    FindingDetailScreen,
)
from beachhead.tui.views.modules import ModulesView
from beachhead.tui.views.runs import RunsView
from beachhead.tui.views.tables import (
    AttackPathsView,
    AuditView,
    CredentialsView,
    FindingsView,
    ResourcesView,
)
from beachhead.tui.views.teardown import TeardownScreen

__all__ = [
    "AttackPathDetailScreen",
    "AttackPathsView",
    "AuditView",
    "CredentialsView",
    "DashboardView",
    "FindingDetailScreen",
    "FindingsView",
    "ModulesView",
    "ResourcesView",
    "RunsView",
    "TeardownScreen",
]
