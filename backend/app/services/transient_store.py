"""TransientStore — short-lived, in-memory, size-capped holder for data that
a detector needs during one request but that must never be persisted
(parsed flow batches, for example; brief §30).

Entries are normally discarded by the caller when the request finishes.
Capacity and TTL limits exist so that a caller that forgets, or crashes
halfway through, can't make memory grow without bound.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from typing import Any


class TransientStore:
    def __init__(self, *, max_entries: int = 16, ttl_s: float = 300.0) -> None:
        self._entries: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._ttl_s = ttl_s

    def put(self, value: Any) -> str:
        key = str(uuid.uuid4())
        with self._lock:
            self._evict()
            self._entries[key] = (time.monotonic(), value)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return key

    def get(self, key: str) -> Any | None:
        with self._lock:
            self._evict()
            item = self._entries.get(key)
            return item[1] if item else None

    def discard(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def _evict(self) -> None:
        cutoff = time.monotonic() - self._ttl_s
        while self._entries and next(iter(self._entries.values()))[0] < cutoff:
            self._entries.popitem(last=False)


flow_batches = TransientStore()
