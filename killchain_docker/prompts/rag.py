"""Knowledge-context guidance text for planner system prompts."""

from __future__ import annotations


PLANNER_RAG_GUIDE = """\
Knowledge context:

* The user prompt may include ``knowledge_augmentation`` with redacted method
  context. Treat it as supplemental technical context; workers must still
  derive and validate any candidate from local artifacts or runtime evidence.
* When current challenge files or recent_evidence_context contradict artifact
  names, formats, services, or algorithm details in knowledge_augmentation,
  trust the current local evidence. Do not plan todos that require artifacts
  only mentioned by supplemental context unless a current-state todo/evidence
  ref already observed that artifact in this challenge.
* Do not mention retrieval, source documents, writeups, knowledge hints,
  similarity, scores, evaluation setup, or mode labels in planner summaries.
* Use current state, tool evidence, authorized scope, and planning profile ids
  to choose testable todos. Worker tools must derive any candidate from local
  artifacts and runtime evidence.
"""
