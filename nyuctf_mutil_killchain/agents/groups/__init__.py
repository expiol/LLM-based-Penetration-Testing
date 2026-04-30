"""Capability-based worker grouping.

Each module under ``groups/`` collects all single-purpose workers that
target one capability area.  These imports register the workers in a single
namespace the orchestrator can discover.

The actual worker classes live in the ``artifact``, ``recon``, ``host``, etc.
modules; this package is a thin organizational layer.
"""

from nyuctf_mutil_killchain.agents.groups.credential import CREDENTIAL_WORKERS
from nyuctf_mutil_killchain.agents.groups.exploit import EXPLOIT_WORKERS
from nyuctf_mutil_killchain.agents.groups.flag import FLAG_WORKERS
from nyuctf_mutil_killchain.agents.groups.host import HOST_WORKERS
from nyuctf_mutil_killchain.agents.groups.solver import SOLVER_WORKERS
from nyuctf_mutil_killchain.agents.groups.static_analysis import STATIC_ANALYSIS_WORKERS
from nyuctf_mutil_killchain.agents.groups.vuln import VULN_WORKERS
from nyuctf_mutil_killchain.agents.groups.web import WEB_WORKERS


def all_worker_classes() -> list[type]:
    """Return every worker class registered across all capability groups."""
    return [
        *STATIC_ANALYSIS_WORKERS,
        *WEB_WORKERS,
        *HOST_WORKERS,
        *CREDENTIAL_WORKERS,
        *EXPLOIT_WORKERS,
        *VULN_WORKERS,
        *FLAG_WORKERS,
        *SOLVER_WORKERS,
    ]


__all__ = [
    "CREDENTIAL_WORKERS",
    "EXPLOIT_WORKERS",
    "FLAG_WORKERS",
    "HOST_WORKERS",
    "SOLVER_WORKERS",
    "STATIC_ANALYSIS_WORKERS",
    "VULN_WORKERS",
    "WEB_WORKERS",
    "all_worker_classes",
]
