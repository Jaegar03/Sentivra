# Sigma rules

`SigmaDetector` loads every `.yml` / `.yaml` file under this directory at startup. Rules stay out of application code (brief §11), so adding or changing one needs no code change.

- `sentivra/`: Sentivra's own starter rules (Apache-2.0).
- Any other subdirectory you add, for example a curated subset of [SigmaHQ](https://github.com/SigmaHQ/sigma), is loaded the same way. SigmaHQ rules are licensed under the Detection Rule License 1.1, which requires attribution when you redistribute them.

## What the engine supports

Single-event rules:
- **Selections:** maps (AND), lists of maps (OR) and keyword lists.
- **Value matching:** wildcards, plus the modifiers `contains`, `startswith`, `endswith`, `all`, `re` (with `i`/`m`/`s`), `cidr`, `exists`, `cased`, `gt`/`gte`/`lt`/`lte` and `windash`.
- **Conditions:** `and`, `or`, `not`, parentheses, `1 of` / `all of` with wildcards, and `them`.

Rules that need anything else (aggregation conditions, `base64`/`base64offset`, placeholders, correlation rules) are **reported as unsupported** by `GET /api/v1/rules` with the reason. They are never partly evaluated.

## Field mapping

Sigma fields map onto Sentivra events as defined in `backend/app/detectors/sigma/fields.py`. If Sentivra doesn't collect a Sigma field (for example `OriginalFileName`), that field is absent, so a rule that needs it doesn't match. It is never approximated.

Two Sentivra extensions:

| Extension | Where | Meaning |
|---|---|---|
| `Signed: 'true' / 'false'` | `process_creation` | Signature status from osquery's `authenticode` (Windows) or `signature` (macOS) tables. Absent when unknown. |
| `category: persistence_item` | logsource | Autostart entries, scheduled tasks, services, cron. Fields: `Kind` (`startup_item`, `scheduled_task`, `service`, `cron`), `Name`, `TargetPath`. |

## ATT&CK tags

`attack.tXXXX` tags are resolved against `detection-rules/custom/attack_index.json` (official ATT&CK data). A tag using a revoked technique ID is remapped to its replacement, and the finding records that it was remapped. For example, the many upstream rules tagged `attack.t1070.001` come out as T1685.005, because ATT&CK v19 revoked T1070.001. A tag the index doesn't know is dropped rather than guessed at.
