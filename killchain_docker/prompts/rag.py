"""Shared RAG guidance text for planner + solver system prompts.

The planner and solver each get their own variant — the planner uses RAG
to bias *task selection* (pick a tighter task title), while the solver
uses RAG to shape its *script body* (pick the right algorithm + offsets).
The two prompts share the same underlying retrieval shape (each entry
carries ``challenge_id`` / ``solution_sketch`` / ``score``) but differ in
how they're allowed to consume it.

Both variants reference the ``related_writeups`` key — the planner reads
it from the user-prompt JSON snapshot, the solver reads it from the
:class:`SolverEvidence.related_writeups` block — so the wording stays in
sync with the augmenter contract in :mod:`knowledge.augmenter`.
"""

from __future__ import annotations

# Score thresholds shared between text + downstream code.  Keep them as
# module constants so the dispatch policy can import the same values
# (avoids the wording drifting from the suppression rule).
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
* These hits are heuristic priors — past challenges that LOOKED similar to
  this one.  Use them to bias your task-type selection: e.g. "the closest
  hit was an LFSR keystream attack → propose solve.generate_script with a
  title that calls out LFSR" or "the closest hit was a multi-time-pad crib
  drag → propose source_review first to confirm the cipher matches".
* When the top hit's ``score`` is at least %(high)s, treat the
  ``solution_sketch`` as a STRONG prior for the next solver task title and
  keep the title tight enough to push the named technique through to the
  solver (the solver agent receives the same writeup hits in its evidence;
  it will run with a focused title).
* When the top hit's ``score`` is below %(weak)s, treat it as weak evidence
  and prefer general exploration tasks first.
* Do NOT propose a flag value from a hit's solution sketch.  Even when the
  retriever surfaces the exact challenge being solved (which can occur
  because self-exclusion is OFF by default), the orchestrator still runs
  ``flag.validate`` against the live target, so guessed flags will fail.
  Use the sketch to pick the right *task type* and a tight task *title*;
  let the solver derive the actual flag from local artifacts.
""" % {"high": HIGH_CONFIDENCE_SCORE, "weak": WEAK_EVIDENCE_SCORE}


SOLVER_RAG_GUIDE = """\
Knowledge-base augmentation (related_writeups in user prompt):

* When the user prompt JSON contains a ``related_writeups`` array, each
  entry is a top-k hit from a corpus of past CTF writeups, ranked by
  dense semantic similarity to the current challenge.  Each hit carries
  ``challenge_id``, ``name``, ``category``, ``files``, ``solution_sketch``
  (the abridged ``## Solution`` body from the past writeup), and a cosine
  ``score``.
* Read ``related_writeups[0].solution_sketch`` BEFORE writing your script.
  When ``score`` is at least %(high)s, the sketch reliably names the exact
  algorithm / offset / constant you need — extract those concrete values
  (cipher name, byte offsets, tap polynomials, key derivation steps) and
  encode them into your solver instead of brute-forcing.
* When ``score`` is between %(weak)s and %(high)s, treat the sketch as a
  shortlist of candidate techniques: try the named approach first, but
  keep a fallback path in the same script.  Below %(weak)s, ignore the
  sketch and rely on the source / binary evidence in the prompt.
* HARD RULE — never ``print`` a flag value taken verbatim from a sketch.
  The validation pipeline checks against the LIVE challenge flag, and
  pasting the sketch's example flag will fail validation while wasting a
  retry.  Always recompute the flag from the bundled artifacts (read
  files in the container, run the algorithm the sketch describes, derive
  the flag bytes).
* When two or more hits agree on the same technique, that is a strong
  signal even if individual scores are mid-range; lean into the shared
  approach rather than treating each hit independently.
""" % {"high": HIGH_CONFIDENCE_SCORE, "weak": WEAK_EVIDENCE_SCORE}
