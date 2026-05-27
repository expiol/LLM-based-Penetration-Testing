"""Knowledge-context guidance text for planner system prompts."""

from __future__ import annotations


PLANNER_KNOWLEDGE_GUIDE = """\
Knowledge context:

* The user prompt may include ``knowledge_augmentation`` with redacted
  reference items. Each item has a ``source``: ``memory`` items come from
  durable cross-run lessons; ``web/*`` items (e.g. ``web/nvd``,
  ``web/mitre``, ``web/exploitdb``) are external priors fetched from public
  cybersecurity feeds.
* Treat both kinds as supplemental context, not as confirmed facts. Workers
  must derive any candidate from local artifacts and runtime evidence.
* When the current challenge files or recent_evidence_context contradict
  artifact names, formats, services, or algorithm details in
  knowledge_augmentation, trust the current local evidence. Do not plan
  todos that require artifacts only mentioned by supplemental context unless
  a current-state todo or evidence ref already observed that artifact in
  this challenge.
* Do not mention retrieval, source documents, writeups, knowledge hints,
  similarity, scores, evaluation setup, or mode labels in planner summaries.
* Use current state, tool evidence, authorized scope, and planning profile
  ids to choose testable todos. Worker tools must derive any candidate from
  local artifacts and runtime evidence.
* If ``policy`` is ``possibly_misleading``, supplemental hints have been
  flagged because earlier attempts based on similar priors stalled; weight
  them less and prefer fresh local evidence.
"""
