"""Category-specific prompt bundles.

Importing this package registers all six CTF categories with the global
registry.  Order does not matter; each module calls :func:`register` at import
time.
"""

from nyuctf_mutil_killchain.prompts.categories import (  # noqa: F401
    crypto,
    forensics,
    misc,
    pwn,
    rev,
    web,
)

__all__: list[str] = []
