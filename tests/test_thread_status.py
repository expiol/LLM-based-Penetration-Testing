from __future__ import annotations

from killchain_docker.thread_status import build_thread_registry


def test_thread_registry_clears_completed_event_work() -> None:
    registry = build_thread_registry(
        challenge="alpha",
        stage="assessment",
        status="running",
        pid=123,
        recent_events=[
            {
                "thread_id": 456,
                "thread_name": "worker",
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "level": "INFO",
                "event_type": "dispatch",
                "message": "running",
                "context": {
                    "todo_id": "todo-1",
                    "todo_status": "running",
                    "todo_phase": "analysis",
                    "worker": "artifact-worker",
                },
            },
            {
                "thread_id": 456,
                "thread_name": "worker",
                "sequence": 2,
                "timestamp": "2026-01-01T00:00:01Z",
                "level": "INFO",
                "event_type": "worker_result",
                "message": "completed",
                "context": {
                    "todo_id": "todo-1",
                    "todo_status": "completed",
                    "todo_phase": "analysis",
                    "worker": "artifact-worker",
                },
            },
        ],
    )

    worker = next(item for item in registry if item["name"] == "worker")
    assert "current_todo" not in worker
    assert worker["latest_event"]["sequence"] == 2
