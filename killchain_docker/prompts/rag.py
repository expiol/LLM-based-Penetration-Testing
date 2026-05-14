"""RAG guidance text for planner system prompts."""

from __future__ import annotations

# Score thresholds shared between text + downstream code.  Keep them as
# module constants so prompts and retrieval policy wording stay aligned.
HIGH_CONFIDENCE_SCORE = 0.6
WEAK_EVIDENCE_SCORE = 0.4


PLANNER_RAG_GUIDE = """\
Knowledge-base augmentation (related_writeups):

* The user prompt may include a ``related_writeups`` array with up to 3 hits
  retrieved from a corpus of past CTF challenges (NYUCTF development split,
  ranked by dense semantic similarity over name + category + description +
  files + ``## Solution`` body).
* Each hit carries: ``challenge_id``, ``name``, ``category``, ``year``,
  ``event``, ``description``, ``files``, ``solution_sketch`` (the abridged
  ``## Solution`` block from the past writeup), and a similarity ``score``
  (cosine in [-1, 1]; higher is more similar).
* These hits are heuristic priors - past challenges that LOOKED similar to
  this one. Use them to bias your task-type selection: e.g. if the closest
  hit was an LFSR keystream attack, propose a specific artifact or exploit
  task that investigates that technique; if it was a multi-time-pad crib
  drag, propose source_review or artifact computation to confirm the cipher.
* When the top hit's ``score`` is at least %(high)s, treat the
  ``solution_sketch`` as a STRONG prior for the next planner task and keep
  the task title focused on one concrete technique or artifact.
* When the top hit's ``score`` is below %(weak)s, treat it as weak evidence
  and prefer general exploration tasks first.
* Do NOT propose a flag value from a hit's solution sketch.  Even when the
  retriever surfaces the exact challenge being solved (which can occur
  because self-exclusion is OFF by default), the orchestrator still runs
  ``flag.validate`` against the live target, so guessed flags will fail.
  Use the sketch to pick the right *task type* and a tight task *title*;
  worker tools must derive the actual flag from local artifacts.
* If the user prompt also contains ``related_writeups_warning``, prior
  attempts that followed the writeup's hint stalled.  Treat the writeup as
  a *possibly misleading* hint: keep its high-level family in mind but
  consider alternative ciphers/algorithms or different parameter parses
  (e.g. endianness, alternative tap polynomials) before repeating the same
  approach.
""" % {"high": HIGH_CONFIDENCE_SCORE, "weak": WEAK_EVIDENCE_SCORE}
