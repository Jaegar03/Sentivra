# SENTIVRA: Future Automation Architecture

**Status: design only.** SENTIVRA detects and explains; a person decides and acts. None of the following exists in this build, and none may be added without an explicit decision to start this work (brief §1, §36):
- a policy engine;
- approval flow or executors;
- n8n, LangGraph, Celery or scheduled workflows;
- automated email, WhatsApp or Telegram actions;
- automated file deletion;
- remediation of any kind.

This document reserves the shape of that future work, so that adding it later means adding components, not rewriting the detection pipeline. It also sets out the guardrails any implementation must meet.

---

## 1. Today's decision chain

```
detectors ──► RiskEngine ──► RiskAssessment ──► alert (OPEN) ──► a person changes its status
                                                                    (PATCH, alerts:write, audited)
```

- Each `DetectionResult` carries a `recommended_action`: `ALLOW`, `MONITOR`, `REVIEW` or `BLOCK` (`app/schemas/detection.py`). The dashboard shows the strongest finding's action.
- **It is advice text only.** Nothing reads it in order to act: not the backend, not the dashboard, not any integration.
- An alert's only state changes are `OPEN` → `ACKNOWLEDGED` → `RESOLVED` (or back to `OPEN`). Each change is made by a person through the API and written to the append-only audit log with the acting client's ID.

These pieces stay. The future design builds on them rather than replacing them.

---

## 2. Target chain

```
Detection ──► Policy Engine ──► Human Approval ──► Automation (executor)
   │               │                  │                   │
   └───────────────┴──── audit log (every step, every actor) ─┘
```

| Stage | Responsibility | Must never |
|---|---|---|
| **Detection** (exists) | Produce findings and one `RiskAssessment` per event | Act on anything |
| **Policy Engine** | Turn an assessment into zero or more *proposed actions*, deterministically, from versioned policy files | Execute, call external APIs, or approve its own proposals |
| **Human Approval** | A person approves or rejects each proposal; approval binds to the exact action | Be bypassed, except for the narrow auto-approval class in [§5](#5-guardrails) |
| **Automation** | Execute approved actions through official APIs, idempotently, with its own least-privilege credentials | Run anything that wasn't approved, or anything outside the action allowlist |

---

## 3. Reserved contracts

Each contract below is specified here, not stubbed in code: an interface with no implementation and no caller can't be tested, and it drifts. The first implementation adds them together with their tests.

### 3.1 Where the chain attaches

`run_pipeline` (`app/services/pipeline.py`) is the single place every ingestion path passes through. After it persists the event, the alert and the audit record, it's the insertion point:

```
assessment = risk_engine.assess(...)
persist event, alert, audit                      # exists today
proposals = policy_engine.evaluate(event, assessment)   # future: pure, no side effects
persist proposals (state PROPOSED), audit         # future
```

Nothing executes in the request path. Executors run in the worker tier ([future-deployment.md](future-deployment.md), Stage 2) and only pick up approved actions.

### 3.2 `PolicyEngine`

- **Input:** a `SecurityEvent`, its `RiskAssessment`, and the findings.
- **Output:** a list of `ProposedAction`s.
- **Pure and deterministic:** the same input and policy version always produce the same proposals.
- **Policies are data, not code:** versioned YAML alongside the other rule packs, loaded with `yaml.safe_load`, and validated against a schema at startup.
- **What a rule can match on:**
  - `severity`, `classification` and `confidence`;
  - the number of *independent* detector categories that agree, which the risk engine already computes for corroboration;
  - `source_type`;
  - the event type and source.

### 3.3 `ProposedAction`

| Field | Meaning |
|---|---|
| `action_id` | UUID; also the executor's idempotency key |
| `alert_id`, `event_id` | What prompted it |
| `action_type` | A member of the closed allowlist ([§4](#4-candidate-action-catalog)). Never a free-form string |
| `target` | Typed per action type (for example, a Gmail message ID). Never a URL or command supplied by the analyzed content |
| `parameters` | Typed per action type; validated against that type's schema |
| `reason` | The policy rule ID and version, plus references to the evidence items that triggered it |
| `reversible` and `undo` | Whether the action can be undone, and how |
| `expires_at` | Proposals that nobody approves expire; they never become approved by waiting |
| `digest` | Hash of `action_type` + `target` + `parameters`. Approval signs this, so nothing can change after approval |

### 3.4 State machine

```
PROPOSED ──approve──► APPROVED ──► EXECUTING ──► SUCCEEDED ──undo──► REVERTED
    │                                  │
    ├──reject──► REJECTED              └──► FAILED (retried idempotently, then left for a person)
    └──timeout─► EXPIRED
```

Every transition is an audit-log entry with its actor: the policy engine's service identity, the approving person, or the executor.

### 3.5 Approval

- **New scopes** extend the existing OAuth2 scope model:
  - `actions:read` to see proposals;
  - `actions:approve` to approve or reject them;
  - `actions:execute`, held only by the executor's service client.
- **Separation of duties:**
  - The policy engine's identity can propose but never approve.
  - The executor can execute but never propose or approve.
  - `alerts:write` does *not* imply `actions:approve`.
- **Approval binds to the digest** from §3.3 and records who approved it and when.
- **Irreversible actions** need a second, different approver, if they're ever allowed at all (see §4).

### 3.6 `ActionExecutor`

- One executor per action type, registered like detectors are today.
- **Contract:** `execute(approved_action) -> result`.
  - Idempotent on `action_id`.
  - Refuses anything that isn't `APPROVED`, whose digest doesn't match, or that has expired.
- **Dry-run mode:** the executor reports what it would have done without doing it.
- **Credentials:** its own least-privilege credentials, separate from ingestion.
  - Example: the Gmail connector reads with `gmail.readonly`. A future quarantine executor would need a separately granted, separately stored modify credential, and nothing else would hold it.

---

## 4. Candidate action catalog

These are future candidates, listed so the allowlist has a starting point. None exists today. Reversible actions come first; irreversible actions are never automatic.

| Action type | Reversible | Needs | Automation stance |
|---|---|---|---|
| `notify_operator` (message the on-call person on a configured channel) | n/a | A notification integration | Approval by default. "Automated email/WhatsApp/Telegram sending" is out of scope for v1 (brief §1) |
| `open_ticket` | Yes (close it) | A ticketing integration | Approval by default |
| `gmail_apply_quarantine_label` | Yes (remove the label) | Gmail modify credential, executor only | Approval required |
| `gmail_move_to_trash` | For 30 days | Same | Approval required |
| `telegram_delete_message` (a group the bot administers) | **No** | Bot admin rights | Never automatic; two-person approval if built at all |
| `firewall_block_ip` (with expiry) | Yes (the block expires or is lifted) | A firewall API integration | Approval required |
| `quarantine_file` (move into an encrypted quarantine store) | Yes (restore) | A native endpoint agent with response capability ([endpoint-agent/README.md](../endpoint-agent/README.md)); osquery is read-only | Approval required |
| Permanent deletion (mail, messages, files) | **No** | — | **Not an action type.** Excluded from the allowlist |

---

## 5. Guardrails

These are requirements. An implementation that misses one isn't ready to ship.

1. **Never act on simulated or demo data.** Proposals for events whose `source_type` is `SIMULATED` or `DEMO_DATA` are recorded as "would propose" at most, and never become executable. The labels that exist today make this checkable.
2. **No single-detector action.** This mirrors principle 1 of the project: no single detector decides. A proposal needs corroboration from at least two independent detector categories, or it is approval-only with no auto-approval possible.
3. **Closed allowlist.** Action types are an enum, and each has a typed target and parameter schema. Nothing derived from analyzed content (an email body, a message, a URL, a filename) is ever used as a command, a URL to call, or code. No "arbitrary API execution" (brief §1).
4. **Human approval is the default.** Auto-approval is possible only if all of these hold:
   - the action type is reversible;
   - it's listed in policy by name;
   - its blast radius is capped (per type, per hour);
   - it's off unless explicitly enabled.

   Every auto-approved action is still audited and visible in the dashboard.
5. **Kill switch.** One setting disables every executor, and it defaults to disabled. Turning it on is an audited, restart-level change.
6. **Shadow mode before anything executes.** The policy engine first runs with no executors enabled, recording what it would have proposed. Those proposals are then compared with what analysts actually did. The measured agreement, on real rather than demo data, is published the way model metrics are in [model-card.md](model-card.md). No executor is enabled on the strength of an unmeasured policy.
7. **Separate credentials, least privilege, and rotation**, as for connectors. Executors never hold ingestion credentials, and vice versa.
8. **Everything is visible.** The dashboard lists every proposal, approval, execution and undo, with its reason and its evidence. Nothing is hidden from the audit log.

---

## 6. Where orchestration tools would fit

The brief names n8n, LangGraph, Celery, scheduled workflows and remediation as possible future systems. None is part of this build. If they're adopted, this is where each belongs, and what it must not be given.

| Tool | Fits as | Must not |
|---|---|---|
| **Celery** (with Redis) | The executor queue: picks up `APPROVED` actions, retries idempotently, records results. Also the worker tier for batch analysis ([future-deployment.md](future-deployment.md), Stage 2) | Be a path around the approval gate: tasks accept an `action_id` and re-check its state and digest themselves |
| **Scheduled workflows** (Celery beat or cron) | Housekeeping: expire stale proposals, enforce retention, re-scan stored hashes after signature updates, re-run model evaluations on a schedule | Take security actions on a timer |
| **n8n** | Downstream delivery of *approved* actions to tools SENTIVRA doesn't integrate natively (ticketing, chat). It receives a signed webhook carrying the action, not the analyzed content | Receive raw message bodies or file content; hold SENTIVRA's API credentials beyond what one workflow needs. Its credential store becomes a high-value target and is threat-modeled as one |
| **LangGraph** (LLM agent workflows) | Analyst assistance only: summarize an alert, draft a triage note, suggest a policy rule for a person to review. Everything it produces is a *proposal* that goes through the same gate | Have tools that execute actions or call external APIs. Its input is attacker-controlled (the emails and messages being analyzed), so it is exposed to prompt injection by design. SENTIVRA's own prompt-injection detection (Phase 4, not built yet) and the approval gate are the mitigations, not trust in the model |
| **Remediation** in general | Only through §3's chain: policy → approval → executor | Exist as a side channel of any tool above |

---

## 7. Existing pieces the design reuses

| Existing | Used for |
|---|---|
| `RecommendedAction` on each finding | Input to policy rules. It remains advice |
| `RiskEngine` corroboration across independent categories | Guardrail 2 |
| `source_type` (`LIVE` / `SIMULATED` / `DEMO_DATA`) on every event | Guardrail 1 |
| OAuth2 client credentials with per-route scopes, the audit log's `actor` | The new `actions:*` scopes; separation of duties; attribution of every step |
| Append-only audit log | The record of every proposal, approval and execution |
| Alert status workflow (`PATCH /alerts/{id}`, `alerts:write`) | Stays the analyst's triage tool; approval is a separate permission on a separate object |
| `DetectorRegistry` pattern | Executor registration |
| Rule packs as data (`detection-rules/`), `yaml.safe_load`, validation at startup | Policy files |

---

## 8. Build order, when this starts

1. Build the policy engine in **shadow mode**: proposals are recorded, nothing can execute. Add a read-only dashboard view titled "Proposed actions (not executed)".
2. Measure the proposals against analyst decisions on live data, and publish the result (guardrail 6).
3. Add the approval gate with the `actions:*` scopes and the state machine, still with no executors enabled.
4. Build the first executor, `notify_operator`, once a notification integration exists. Keep it behind the kill switch and dry-run first.
5. Add reversible actions, one at a time, each with approval required.
6. Only then consider auto-approval, for named reversible action types with capped blast radius.

Each step is its own decision. Reaching one step doesn't commit the project to the next.
