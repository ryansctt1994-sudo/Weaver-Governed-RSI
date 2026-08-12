"""Append-only, canonical JSON hash-chain ledger."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    sequence: int
    recorded_at: str
    previous_hash: str
    event: Mapping[str, Any]
    record_hash: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "previous_hash": self.previous_hash,
            "event": dict(self.event),
        }


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    valid: bool
    failure_index: int | None = None
    reason: str | None = None


class AppendOnlyLedger:
    """In-memory ledger with explicit export/import and serialized appends."""

    def __init__(self, records: Iterable[LedgerRecord] = ()) -> None:
        self._lock = RLock()
        self._records = list(records)

    @staticmethod
    def _hash(unsigned: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json(unsigned)).hexdigest()

    def append(self, event: Mapping[str, Any], *, recorded_at: str) -> LedgerRecord:
        if not recorded_at:
            raise ValueError("recorded_at is required")
        with self._lock:
            sequence = len(self._records)
            previous_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
            copied_event = dict(event)
            unsigned = {
                "sequence": sequence,
                "recorded_at": recorded_at,
                "previous_hash": previous_hash,
                "event": copied_event,
            }
            record = LedgerRecord(
                sequence=sequence,
                recorded_at=recorded_at,
                previous_hash=previous_hash,
                event=copied_event,
                record_hash=self._hash(unsigned),
            )
            self._records.append(record)
            return record

    @property
    def records(self) -> tuple[LedgerRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def verify(self) -> LedgerVerification:
        previous = GENESIS_HASH
        with self._lock:
            for index, record in enumerate(self._records):
                if record.sequence != index:
                    return LedgerVerification(False, index, "non-contiguous sequence")
                if record.previous_hash != previous:
                    return LedgerVerification(False, index, "previous hash mismatch")
                if self._hash(record.unsigned_dict()) != record.record_hash:
                    return LedgerVerification(False, index, "record hash mismatch")
                previous = record.record_hash
        return LedgerVerification(True)

    def write_jsonl(self, path: Path) -> None:
        """Export a complete snapshot without providing an in-place mutation API."""

        data = b"".join(canonical_json(asdict(record)) + b"\n" for record in self.records)
        path.write_bytes(data)

    @classmethod
    def read_jsonl(cls, path: Path) -> AppendOnlyLedger:
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = json.loads(line)
            records.append(LedgerRecord(**raw))
        return cls(records)
