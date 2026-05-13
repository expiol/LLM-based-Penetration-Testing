"""LLM-driven solver pipeline split into single-purpose components.

Public surface:

- :class:`SolverAgent` - the single worker registered with the orchestrator.
- :class:`SolverEvidence` / :class:`SolverEvidenceComposer` - data assembly.
- :class:`SolverPromptBuilder` - prompt rendering.
- :class:`SolverCodeExecutor` / :class:`SolverExecutionOutcome` - container call.
- :class:`SolverResultParser` / :class:`SolverFlagSet` - flag extraction.
- :class:`SolverRetryPolicy` / :class:`SolverRetryPlan` - retry decisions.
"""

from killchain_docker.agents.solver.agent import SolverAgent
from killchain_docker.agents.solver.evidence import (
    SolverEvidence,
    SolverEvidenceComposer,
)
from killchain_docker.agents.solver.executor import (
    SolverCodeExecutor,
    SolverExecutionOutcome,
)
from killchain_docker.agents.solver.failure import (
    SolverFailureClassifier,
    SolverFailureSignal,
)
from killchain_docker.agents.solver.parser import (
    SolverFlagSet,
    SolverResultParser,
)
from killchain_docker.agents.solver.prompts import SolverPromptBuilder
from killchain_docker.agents.solver.retry import (
    SolverRetryPlan,
    SolverRetryPolicy,
)

__all__ = [
    "SolverAgent",
    "SolverCodeExecutor",
    "SolverEvidence",
    "SolverEvidenceComposer",
    "SolverExecutionOutcome",
    "SolverFailureClassifier",
    "SolverFailureSignal",
    "SolverFlagSet",
    "SolverPromptBuilder",
    "SolverResultParser",
    "SolverRetryPlan",
    "SolverRetryPolicy",
]
