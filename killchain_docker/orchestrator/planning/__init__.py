"""Task planning pipeline split into single-responsibility modules.

- :class:`PlannedTask` / :class:`PlannerDecision` - LLM output schemas
- :class:`TaskPlanner` - abstract base
- :class:`BootstrapSeeder` - inject mandatory seed tasks (artifact.triage, recon.enumerate_scope)
- :class:`PlanStrategy` - LLM proposal of next tasks
- :class:`TaskNormalizer` - fill missing input_context from challenge metadata + assets
- :class:`TaskDeduper` - drop tasks with already-known dedupe_keys
- :class:`LLMPlanner` - thin pipeline orchestrator wiring the four pieces

No tasks are filtered, suppressed, or capped here.  The LLM owns
prioritization and stopping decisions.
"""

from killchain_docker.orchestrator.planning.bootstrap import BootstrapSeeder
from killchain_docker.orchestrator.planning.deduper import TaskDeduper
from killchain_docker.orchestrator.planning.normalizer import TaskNormalizer
from killchain_docker.orchestrator.planning.planner import LLMPlanner
from killchain_docker.orchestrator.planning.schemas import (
    PlannedTask,
    PlannerDecision,
    TaskPlanner,
)
from killchain_docker.orchestrator.planning.strategy import PlanStrategy

__all__ = [
    "BootstrapSeeder",
    "LLMPlanner",
    "PlanStrategy",
    "PlannedTask",
    "PlannerDecision",
    "TaskDeduper",
    "TaskNormalizer",
    "TaskPlanner",
]
