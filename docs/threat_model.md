# Threat Model

AutoPentest is intended for authorized security research only.

## Assumptions

- Operators supply explicit authorization with `--i-understand-and-am-authorized`.
- Targets are limited to the local lab or approved scopes.

## Misuse risks

- Running tools outside authorized scope.
- Misinterpreting findings as exploit-ready results.
- Data leakage via logs or artifacts.

## Mitigations

- Safety allowlist for command execution (`core/safety.py`).
- Scope enforcement via target scope + host allowlist.
- sqlmap runs in detection mode only (no dump/file/OS shell).
- Evidence is stored locally and is user-controlled.
