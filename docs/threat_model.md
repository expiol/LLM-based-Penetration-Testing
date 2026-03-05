# Threat Model

AutoPentest is intended for authorized security research only.

## Assumptions

- Operators supply explicit scope declarations.
- Targets are provided by the user and are authorized.

## Misuse risks

- Running tools outside authorized scope.
- Misinterpretation of results as exploitation.
- Data leakage via logs or artifacts.

## Mitigations

- CLI requires explicit scope declaration.
- Scope validation enforces target allowlists.
- No exploit payloads or destructive actions are included.
- Evidence is stored locally and is user-controlled.
