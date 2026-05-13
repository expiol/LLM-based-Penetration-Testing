"""Internal helpers shared across worker agents.

These modules live at L2.5 in the layering: above ``state`` but below the
worker classes.  They contain pure functions with no LLM, no execution-plane,
and no task-construction concerns.

- ``flag``: extract / decode flag-shaped tokens.
- ``network``: web URL / scheme / banner inference and context resolution.
- ``strings``: generic list/string normalization helpers.
"""
