"""Execution and exploitation fact stores."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.fact_merges import (
    merge_endpoint,
    merge_exploit_attempt,
    merge_hypothesis,
    merge_route,
    merge_session,
    merge_vulnerability,
)
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import (
        Endpoint,
        ExploitAttempt,
        Hypothesis,
        Route,
        Session,
        Vulnerability,
    )
    from killchain_docker.state.run_state import RunState


class ExecutionFactStore:
    """Mutable store for execution-stage derived facts."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def endpoint(self, endpoint: "Endpoint", *, touch: bool = True) -> None:
        if endpoint.endpoint_id in self.state.endpoints:
            merge_endpoint(self.state.endpoints[endpoint.endpoint_id], endpoint)
        else:
            self.state.endpoints[endpoint.endpoint_id] = endpoint
        if touch:
            self.maintenance.touch()

    def route(self, route: "Route", *, touch: bool = True) -> None:
        if route.route_id in self.state.routes:
            merge_route(self.state.routes[route.route_id], route)
        else:
            self.state.routes[route.route_id] = route
        if touch:
            self.maintenance.touch()

    def hypothesis(self, hypothesis: "Hypothesis", *, touch: bool = True) -> None:
        if hypothesis.hypothesis_id in self.state.hypotheses:
            merge_hypothesis(
                self.state.hypotheses[hypothesis.hypothesis_id], hypothesis
            )
        else:
            self.state.hypotheses[hypothesis.hypothesis_id] = hypothesis
        if touch:
            self.maintenance.touch()

    def vulnerability(
        self, vulnerability: "Vulnerability", *, touch: bool = True
    ) -> None:
        if vulnerability.vulnerability_id in self.state.vulnerabilities:
            merge_vulnerability(
                self.state.vulnerabilities[vulnerability.vulnerability_id],
                vulnerability,
            )
        else:
            self.state.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
        if touch:
            self.maintenance.touch()

    def exploit_attempt(self, attempt: "ExploitAttempt", *, touch: bool = True) -> None:
        attempt.task_id = attempt.task_id or ""
        if attempt.attempt_id in self.state.exploit_attempts:
            merge_exploit_attempt(
                self.state.exploit_attempts[attempt.attempt_id], attempt
            )
        else:
            self.state.exploit_attempts[attempt.attempt_id] = attempt
        if touch:
            self.maintenance.touch()

    def session(self, session: "Session", *, touch: bool = True) -> None:
        if session.session_id in self.state.sessions:
            merge_session(self.state.sessions[session.session_id], session)
        else:
            self.state.sessions[session.session_id] = session
        if touch:
            self.maintenance.touch()
