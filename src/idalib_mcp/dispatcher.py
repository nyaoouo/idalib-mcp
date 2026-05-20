from __future__ import annotations

import json
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import Any, Callable


class CancelledError(Exception):
    """Raised when a dispatcher run is cancelled."""


@dataclass
class RequestRecord:
    id: str
    json_rpc_id: Any
    session_id: str
    tool: str
    enqueued_at: float
    started_at: float | None = None
    finished_at: float | None = None
    status: str = "queued"
    duration_ms: float | None = None
    args_preview: str = ""
    args_full_id: str | None = None
    result_preview: str | None = None
    result_full_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PREVIEW_CHARS = 500


def _serialize(value: Any) -> str:
    try:
        return json.dumps(value, separators=(",", ":"), default=str)
    except Exception:
        return str(value)


def _make_preview(value: Any) -> tuple[str, str | None]:
    """Return (preview, full_text_if_truncated)."""
    text = _serialize(value)
    if len(text) <= PREVIEW_CHARS:
        return text, None
    return f"{text[:PREVIEW_CHARS]}…[{len(text)} chars total]", text


class WorkerDispatcher:
    HISTORY_CAP = 100
    PAYLOAD_CAP = 200

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        # RLock: _enqueue calls _store_payload while already holding this lock.
        self._state_lock = threading.RLock()
        self._serial_lock = threading.Lock()
        self._pending: "OrderedDict[str, RequestRecord]" = OrderedDict()
        self._current: RequestRecord | None = None
        self._history: deque[RequestRecord] = deque(maxlen=self.HISTORY_CAP)
        self._payloads: "OrderedDict[str, str]" = OrderedDict()

    # --- public snapshot -------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "session_id": self.session_id,
                "current": self._current.to_dict() if self._current else None,
                "queued": [r.to_dict() for r in self._pending.values()],
                "history": [r.to_dict() for r in self._history],
            }

    def get_payload(self, payload_id: str) -> str | None:
        with self._state_lock:
            return self._payloads.get(payload_id)

    # --- main entry ------------------------------------------------------

    def run(
        self,
        tool: str,
        json_rpc_id: Any,
        args: dict[str, Any],
        fn: Callable[[threading.Event], Any],
        cancel_event: threading.Event,
    ) -> Any:
        record = self._enqueue(tool, json_rpc_id, args)
        try:
            self._acquire_with_cancel(cancel_event)
        except CancelledError:
            self._finish_cancelled(record)
            raise

        try:
            with self._state_lock:
                self._pending.pop(record.id, None)
                self._current = record
                record.status = "running"
                record.started_at = time.time()

            if cancel_event.is_set():
                raise CancelledError("Cancelled before execution")

            result = fn(cancel_event)
            self._finish_ok(record, result)
            return result
        except CancelledError:
            self._finish_cancelled(record)
            raise
        except Exception as exc:
            self._finish_error(record, exc)
            raise
        finally:
            with self._state_lock:
                if self._current is record:
                    self._current = None
            self._serial_lock.release()

    # --- internals -------------------------------------------------------

    def _enqueue(self, tool: str, json_rpc_id: Any, args: dict[str, Any]) -> RequestRecord:
        record_id = uuid.uuid4().hex[:8]
        args_preview, args_full = _make_preview(args)
        record = RequestRecord(
            id=record_id,
            json_rpc_id=json_rpc_id,
            session_id=self.session_id,
            tool=tool,
            enqueued_at=time.time(),
            args_preview=args_preview,
        )
        with self._state_lock:
            if args_full is not None:
                args_full_id = f"{record_id}.args"
                record.args_full_id = args_full_id
                self._store_payload(args_full_id, args_full)
            self._pending[record_id] = record
        return record

    def _acquire_with_cancel(self, cancel_event: threading.Event) -> None:
        while True:
            if cancel_event.is_set():
                raise CancelledError("Cancelled while queued")
            if self._serial_lock.acquire(timeout=0.5):
                return

    def _finish_ok(self, record: RequestRecord, result: Any) -> None:
        result_preview, result_full = _make_preview(result)
        with self._state_lock:
            record.status = "ok"
            record.finished_at = time.time()
            record.duration_ms = max(0.0, (record.finished_at - (record.started_at or record.enqueued_at)) * 1000.0)
            record.result_preview = result_preview
            if result_full is not None:
                result_full_id = f"{record.id}.result"
                record.result_full_id = result_full_id
                self._store_payload(result_full_id, result_full)
            self._history.append(record)

    def _finish_error(self, record: RequestRecord, exc: BaseException) -> None:
        with self._state_lock:
            record.status = "error"
            record.finished_at = time.time()
            base = record.started_at or record.enqueued_at
            record.duration_ms = max(0.0, (record.finished_at - base) * 1000.0)
            record.error = str(exc)
            self._history.append(record)

    def _finish_cancelled(self, record: RequestRecord) -> None:
        with self._state_lock:
            self._pending.pop(record.id, None)
            record.status = "cancelled"
            record.finished_at = time.time()
            base = record.started_at or record.enqueued_at
            record.duration_ms = max(0.0, (record.finished_at - base) * 1000.0)
            self._history.append(record)

    def _store_payload(self, key: str, text: str) -> None:
        self._payloads[key] = text
        while len(self._payloads) > self.PAYLOAD_CAP:
            self._payloads.popitem(last=False)
