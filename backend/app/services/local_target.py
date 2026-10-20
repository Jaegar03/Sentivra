"""Loopback-only synthetic target for the Cyber Defense Lab.

The target has no database, filesystem, subprocess, or network access. Its
protected operation is an in-memory search over fixed synthetic records and is
called only after the simulation enforcement decision has been made.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class TargetResponse:
    endpoint: str
    status_code: int
    body: dict[str, Any]
    protected_operation_executed: bool


class SyntheticSearchTarget:
    endpoint = "synthetic://search-target/search"

    def __init__(self) -> None:
        self._records = (
            {"id": "doc-1", "title": "Security review", "body": "Local demonstration record"},
            {"id": "doc-2", "title": "Incident response", "body": "Synthetic response playbook"},
        )
        self._protected_operation_count = 0

    @property
    def protected_operation_count(self) -> int:
        return self._protected_operation_count

    def reset(self) -> None:
        self._protected_operation_count = 0

    def search(
        self,
        *,
        request_id: str,
        query: str,
        enforcement: str,
        timeline: list[dict[str, str]] | None = None,
    ) -> TargetResponse:
        if timeline is not None:
            timeline.append({"stage": "target_handler_entered", "timestamp": datetime.now(UTC).isoformat()})
        if enforcement == "BLOCKED":
            if timeline is not None:
                timeline.append({"stage": "protected_operation_not_executed", "timestamp": datetime.now(UTC).isoformat()})
            return TargetResponse(
                endpoint=self.endpoint,
                status_code=403,
                protected_operation_executed=False,
                body={"status": "REJECTED_BEFORE_EXECUTION", "reason": "Simulation enforcement rejected the request.", "request_id": request_id},
            )
        if enforcement != "ALLOWED":
            if timeline is not None:
                timeline.append({"stage": "protected_operation_not_executed", "timestamp": datetime.now(UTC).isoformat()})
            return TargetResponse(
                endpoint=self.endpoint,
                status_code=202,
                protected_operation_executed=False,
                body={"status": "NOT_EXECUTED", "reason": "The simulation policy did not permit the protected operation.", "request_id": request_id},
            )
        if timeline is not None:
            timeline.append({"stage": "protected_operation_entered", "timestamp": datetime.now(UTC).isoformat()})
        self._protected_operation_count += 1
        needle = query.casefold()
        matches = [record for record in self._records if needle in record["title"].casefold() or needle in record["body"].casefold()]
        if timeline is not None:
            timeline.append({"stage": "protected_operation_completed", "timestamp": datetime.now(UTC).isoformat()})
        return TargetResponse(
            endpoint=self.endpoint,
            status_code=200,
            protected_operation_executed=True,
            body={"status": "EXECUTED", "request_id": request_id, "results": matches},
        )


synthetic_search_target = SyntheticSearchTarget()
