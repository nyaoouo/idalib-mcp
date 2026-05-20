from __future__ import annotations

import select
import socket
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CancelHandle:
    request_id: Any
    event: threading.Event = field(default_factory=threading.Event)
    socket_ref: "weakref.ReferenceType | None" = None


class CancellationRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handles: dict[Any, CancelHandle] = {}

    def register(self, request_id: Any) -> CancelHandle:
        handle = CancelHandle(request_id=request_id)
        with self._lock:
            self._handles[request_id] = handle
        return handle

    def unregister(self, request_id: Any) -> None:
        with self._lock:
            self._handles.pop(request_id, None)

    def cancel(self, request_id: Any) -> bool:
        with self._lock:
            handle = self._handles.get(request_id)
        if handle is None:
            return False
        handle.event.set()
        return True

    def snapshot(self) -> list[Any]:
        with self._lock:
            return list(self._handles.keys())


_request_context = threading.local()


def set_active_socket(sock: "socket.socket | None") -> None:
    _request_context.socket = sock


def get_active_socket() -> "socket.socket | None":
    return getattr(_request_context, "socket", None)


def spawn_socket_watcher(
    handle: CancelHandle,
    sock: "socket.socket",
    stop: threading.Event,
) -> threading.Thread:
    """Spawn a daemon thread that sets `handle.event` if `sock` closes."""
    handle.socket_ref = weakref.ref(sock)

    def watch() -> None:
        while not stop.is_set():
            try:
                r, _, _ = select.select([sock], [], [], 0.5)
            except (OSError, ValueError):
                handle.event.set()
                return
            if not r:
                continue
            try:
                peek = sock.recv(1, socket.MSG_PEEK)
            except (OSError, ConnectionError):
                handle.event.set()
                return
            if peek == b"":
                handle.event.set()
                return

    thread = threading.Thread(target=watch, name=f"cancel-watch-{handle.request_id}", daemon=True)
    thread.start()
    return thread
