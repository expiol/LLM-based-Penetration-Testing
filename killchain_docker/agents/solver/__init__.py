"""LLM-driven solver pipeline split into single-purpose components.

Public surface:

- :class:`SolverAgent` - the single worker registered with the orchestrator.
- :class:`SolverEvidence` / :class:`SolverEvidenceComposer` - data assembly.
- :class:`SolverPromptBuilder` - prompt rendering.
- :class:`SolverCodeExecutor` / :class:`SolverExecutionOutcome` - container call.
- :class:`SolverResultParser` / :class:`SolverFlagSet` - flag extraction.
- :class:`SolverRetryPolicy` / :class:`SolverRetryPlan` - retry decisions.
"""

from nyuctf_mutil_killchain.agents.solver.agent import SolverAgent
from nyuctf_mutil_killchain.agents.solver.evidence import (
    SolverEvidence,
    SolverEvidenceComposer,
)
from nyuctf_mutil_killchain.agents.solver.executor import (
    SolverCodeExecutor,
    SolverExecutionOutcome,
)
from nyuctf_mutil_killchain.agents.solver.failure import (
    SolverFailureClassifier,
    SolverFailureSignal,
)
from nyuctf_mutil_killchain.agents.solver.parser import (
    SolverFlagSet,
    SolverResultParser,
)
from nyuctf_mutil_killchain.agents.solver.prompts import SolverPromptBuilder
from nyuctf_mutil_killchain.agents.solver.retry import (
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
