# Local Attack-and-Defense Demonstration

The Cyber Defense Lab's `sqli-indicator` scenario now exercises a real,
in-process request lifecycle against a dedicated synthetic target:

```text
trusted SQL fixture
  -> SQLInjectionDetector
  -> RiskEngine
  -> simulation enforcement boundary
  -> synthetic search target (only when ALLOWED)
```

The target is `synthetic://search-target/search`. It is not a network listener,
does not use a database, filesystem, subprocess, or external service, and only
searches two fixed in-memory records. Its protected operation increments an
in-memory counter so tests can prove that a blocked request did not execute it.

## Outcomes

- `DETECTED` + `BLOCKED` returns HTTP 403-shaped target output and
  `REJECTED_BEFORE_EXECUTION`; the protected operation is not called.
- A benign control uses the same target with the prompt detector and returns
  `NOT_DETECTED` + `ALLOWED`; the protected operation executes against the
  synthetic records.
- Detector errors, unavailable detectors, timeouts, and partial results fail
  closed for the target and use `ENFORCEMENT_UNAVAILABLE` / `NOT_EXECUTED`.

Detection and enforcement are separate fields. A block is reported only after
the target confirms that the protected operation did not execute.

The command center provides explicit **Run SQL injection test**, **Run benign
control**, and **Run both scenarios** controls. The comparison panel is populated
from the returned execution records, not from a client-side verdict. Each target
run records request creation, detection, enforcement, target-handler entry,
protected-operation entry/completion or non-execution, target response, and
execution completion.

## API and reset

The existing authenticated simulation endpoints remain the entry point:

- `GET /api/simulation/scenarios`
- `POST /api/simulation/run`
- `GET /api/simulation/runs`
- `GET /api/simulation/runs/{execution_id}`
- `POST /api/simulation/target/reset` — resets only in-memory target state; it
  does not delete Sentivra events, alerts, or execution history.

Start the backend and frontend normally, sign in, open **Cyber Defense Lab**,
choose **SQL injection indicator**, and select **Start attack simulation**.
The result panel shows detector evidence, the enforcement result, target status,
protected-operation execution state, and linked event/alert IDs.

No real SQL, packets, URL requests, files, credentials, or external services
are involved.
