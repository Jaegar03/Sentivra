"""EventRepository — the only module that reads/writes EventORM rows.

This is the seam docs/architecture.md §2 describes: swapping SQLite for
PostgreSQL later means changing app.core.database's connection string, not
this file's call sites elsewhere in the app.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.schema import SecurityEvent
from app.models.orm import EventORM


class EventRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create_if_absent(self, event: SecurityEvent) -> EventORM:
        existing = self._db.get(EventORM, event.event_id)
        if existing is not None:
            return existing

        row = EventORM(
            event_id=event.event_id,
            event_type=event.event_type.value,
            timestamp=event.timestamp,
            source=event.source,
            source_type=event.source_type.value,
            user_id=event.user_id,
            payload_json=event.model_dump_json(),
        )
        self._db.add(row)
        self._db.commit()
        self._db.refresh(row)
        return row

    def get(self, event_id: str) -> EventORM | None:
        return self._db.get(EventORM, event_id)

    def summaries(self, event_ids: list[str]) -> dict[str, dict]:
        """Source, source type and event type for each id, from the indexed
        columns only (no JSON parsing), for annotating alert lists."""
        if not event_ids:
            return {}
        stmt = select(EventORM.event_id, EventORM.source, EventORM.source_type, EventORM.event_type).where(
            EventORM.event_id.in_(set(event_ids)))
        return {r.event_id: {"source": r.source, "source_type": r.source_type, "event_type": r.event_type}
                for r in self._db.execute(stmt)}

    def list_recent(self, limit: int = 50, offset: int = 0) -> list[EventORM]:
        stmt = (
            select(EventORM)
            .order_by(EventORM.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._db.execute(stmt).scalars())

    def to_domain(self, row: EventORM) -> SecurityEvent:
        return SecurityEvent.model_validate_json(row.payload_json)
