"""Unit tests for the cross-run durable memory system."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from killchain_docker.memory.durable import (
    DurableMemoryRecord,
    DurableMemoryScope,
    DurableMemoryUpdate,
    coerce_durable_updates,
)
from killchain_docker.memory.persistence import (
    DurableMemoryStore,
    INDEX_NAME,
    slugify,
)
from killchain_docker.prompt_projection import cross_run_memory as project_cross_run_memory
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import WorkerResult
from killchain_docker.state.worker_results import WorkerResultApplier


class CoerceDurableUpdatesTests(unittest.TestCase):
    def test_dict_input_uses_keys_as_keys(self) -> None:
        updates = coerce_durable_updates({"k1": "v1", "k2": "v2"})
        self.assertEqual({u.key for u in updates}, {"k1", "k2"})
        self.assertTrue(all(u.scope == DurableMemoryScope.CHALLENGE for u in updates))

    def test_list_of_dicts_with_explicit_scope(self) -> None:
        updates = coerce_durable_updates(
            [
                {"key": "k", "value": "v", "scope": "global"},
                {"key": "c", "value": "vc", "scope": "category"},
                {"key": "x", "value": ""},  # filtered: empty value
            ]
        )
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[0].scope, DurableMemoryScope.GLOBAL)
        self.assertEqual(updates[1].scope, DurableMemoryScope.CATEGORY)

    def test_unknown_scope_falls_back_to_challenge(self) -> None:
        updates = coerce_durable_updates([{"key": "k", "value": "v", "scope": "weird"}])
        self.assertEqual(updates[0].scope, DurableMemoryScope.CHALLENGE)

    def test_filters_empty_keys(self) -> None:
        self.assertEqual(coerce_durable_updates([{"key": "", "value": "v"}]), [])
        self.assertEqual(coerce_durable_updates(None), [])
        self.assertEqual(coerce_durable_updates("not-a-collection"), [])


class SlugifyTests(unittest.TestCase):
    def test_basic_slug(self) -> None:
        self.assertEqual(slugify("Hello World!"), "hello-world")

    def test_fallback_on_empty(self) -> None:
        self.assertEqual(slugify("***", fallback="fb"), "fb")

    def test_truncation(self) -> None:
        slug = slugify("a" * 200)
        self.assertLessEqual(len(slug), 80)


class DurableMemoryStoreRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "memory"
        self.store = DurableMemoryStore(self.root)

    def test_apply_and_load_global_scope(self) -> None:
        updates = [
            DurableMemoryUpdate(
                key="ssh banners reveal versions",
                value="banner grabs are reliable",
                scope=DurableMemoryScope.GLOBAL,
                title="SSH banners",
            )
        ]
        self.store.apply_updates(
            updates, run_id="run-1", category="recon", challenge="warmup"
        )
        loaded = self.store.load_relevant(category="recon", challenge="warmup")
        self.assertEqual(len(loaded), 1)
        record = loaded[0]
        self.assertEqual(record.key, "ssh banners reveal versions")
        self.assertEqual(record.scope, DurableMemoryScope.GLOBAL)
        self.assertIn("run-1", record.run_ids)

    def test_apply_merges_existing_record_and_appends_run(self) -> None:
        update = DurableMemoryUpdate(
            key="repeat-fact",
            value="first version",
            scope=DurableMemoryScope.CHALLENGE,
        )
        self.store.apply_updates(
            [update], run_id="run-1", category="cat", challenge="ch"
        )
        update2 = DurableMemoryUpdate(
            key="repeat-fact",
            value="second version",
            scope=DurableMemoryScope.CHALLENGE,
        )
        self.store.apply_updates(
            [update2], run_id="run-2", category="cat", challenge="ch"
        )
        loaded = self.store.load_relevant(category="cat", challenge="ch")
        self.assertEqual(len(loaded), 1)
        record = loaded[0]
        self.assertEqual(record.value, "second version")
        self.assertEqual(record.run_ids, ["run-1", "run-2"])

    def test_scope_routing_filters_unrelated_categories(self) -> None:
        self.store.apply_updates(
            [DurableMemoryUpdate(key="cat-a", value="a", scope=DurableMemoryScope.CATEGORY)],
            run_id="r",
            category="alpha",
            challenge="ch",
        )
        self.store.apply_updates(
            [DurableMemoryUpdate(key="cat-b", value="b", scope=DurableMemoryScope.CATEGORY)],
            run_id="r",
            category="beta",
            challenge="ch",
        )
        only_alpha = self.store.load_relevant(category="alpha", challenge=None)
        keys = {record.key for record in only_alpha}
        self.assertEqual(keys, {"cat-a"})

    def test_unique_slug_when_keys_collide_after_slugify(self) -> None:
        self.store.apply_updates(
            [DurableMemoryUpdate(key="hello world", value="v1", scope=DurableMemoryScope.GLOBAL)],
            run_id="r",
            category="c",
            challenge="ch",
        )
        # Different key, same slug post-normalization.
        self.store.apply_updates(
            [DurableMemoryUpdate(key="HELLO/WORLD", value="v2", scope=DurableMemoryScope.GLOBAL)],
            run_id="r",
            category="c",
            challenge="ch",
        )
        global_dir = self.root / "global"
        files = sorted(p.name for p in global_dir.glob("*.md") if p.name != INDEX_NAME)
        self.assertIn("hello-world.md", files)
        self.assertIn("hello-world-2.md", files)

    def test_writes_index_files(self) -> None:
        self.store.apply_updates(
            [DurableMemoryUpdate(key="k", value="v", scope=DurableMemoryScope.GLOBAL)],
            run_id="r",
            category="c",
            challenge="ch",
        )
        self.assertTrue((self.root / "global" / INDEX_NAME).exists())
        self.assertTrue((self.root / INDEX_NAME).exists())

    def test_load_relevant_on_empty_dir_returns_empty_list(self) -> None:
        self.assertEqual(self.store.load_relevant(category="x", challenge="y"), [])


class WorkerResultApplierRoutesDurableUpdatesTests(unittest.TestCase):
    def test_pending_durable_updates_appended_on_apply(self) -> None:
        from killchain_docker.orchestrator.todo.queue import TodoQueue
        from killchain_docker.state.todos import TodoItem, TodoPhase

        state = RunState(objective="o", authorized_scope=["scope"])
        todo = TodoItem(todo_id="todo-1", goal="g", phase=TodoPhase.RECON)
        TodoQueue(state).enqueue(todo)
        applier = WorkerResultApplier(state)
        result = WorkerResult(
            todo_id="todo-1",
            worker_name="recon-worker",
            success=True,
            summary="ok",
            durable_memory_updates=[
                DurableMemoryUpdate(
                    key="lesson",
                    value="something durable",
                    scope=DurableMemoryScope.GLOBAL,
                )
            ],
        )
        applier.apply(result)
        self.assertEqual(len(state.pending_durable_memory_updates), 1)
        self.assertEqual(state.pending_durable_memory_updates[0].key, "lesson")


class CrossRunMemoryProjectionTests(unittest.TestCase):
    def test_projects_records_with_scope_and_truncation(self) -> None:
        state = RunState(objective="o", authorized_scope=["s"])
        state.cross_run_memory = [
            DurableMemoryRecord(
                slug="long",
                key="long-key",
                value="x" * 1000,
                scope=DurableMemoryScope.CHALLENGE,
                category="cat",
                challenge="ch",
                title="Long",
            ),
            DurableMemoryRecord(
                slug="short",
                key="short",
                value="ok",
                scope=DurableMemoryScope.GLOBAL,
                title="Short",
            ),
        ]
        projected = project_cross_run_memory(state, width=50)
        self.assertEqual(len(projected), 2)
        long_entry = next(item for item in projected if item["key"] == "long-key")
        self.assertLessEqual(len(long_entry["value"]), 50)
        self.assertTrue(long_entry["value"].endswith("…"))
        scopes = {item["scope"] for item in projected}
        self.assertEqual(scopes, {"challenge", "global"})


if __name__ == "__main__":
    unittest.main()
