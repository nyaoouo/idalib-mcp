from __future__ import annotations

import socket
import threading
import time
import unittest

from idalib_mcp.cancellation import (
    CancellationRegistry,
    spawn_socket_watcher,
    set_active_socket,
    get_active_socket,
)


class CancellationRegistryTests(unittest.TestCase):
    def test_register_unregister_cancel(self) -> None:
        registry = CancellationRegistry()
        handle = registry.register("req-1")
        self.assertFalse(handle.event.is_set())

        self.assertTrue(registry.cancel("req-1"))
        self.assertTrue(handle.event.is_set())

        registry.unregister("req-1")
        self.assertFalse(registry.cancel("req-1"))

    def test_cancel_unknown_returns_false(self) -> None:
        registry = CancellationRegistry()
        self.assertFalse(registry.cancel("nope"))

    def test_register_duplicate_returns_new_handle(self) -> None:
        registry = CancellationRegistry()
        h1 = registry.register("req-1")
        h2 = registry.register("req-1")
        self.assertIsNot(h1, h2)
        registry.cancel("req-1")
        self.assertTrue(h2.event.is_set())


class SocketWatcherTests(unittest.TestCase):
    def test_watcher_sets_event_when_peer_closes(self) -> None:
        registry = CancellationRegistry()
        handle = registry.register("req-1")
        a, b = socket.socketpair()
        try:
            stop = threading.Event()
            watcher = spawn_socket_watcher(handle, a, stop)
            try:
                b.close()
                self.assertTrue(handle.event.wait(timeout=2))
            finally:
                stop.set()
                watcher.join(timeout=2)
        finally:
            a.close()

    def test_watcher_exits_when_stop_set(self) -> None:
        registry = CancellationRegistry()
        handle = registry.register("req-1")
        a, b = socket.socketpair()
        try:
            stop = threading.Event()
            watcher = spawn_socket_watcher(handle, a, stop)
            time.sleep(0.05)
            stop.set()
            watcher.join(timeout=2)
            self.assertFalse(watcher.is_alive())
            self.assertFalse(handle.event.is_set())
        finally:
            a.close()
            b.close()


class ActiveSocketThreadLocalTests(unittest.TestCase):
    def test_set_and_get(self) -> None:
        self.assertIsNone(get_active_socket())
        sentinel = object()
        set_active_socket(sentinel)
        try:
            self.assertIs(get_active_socket(), sentinel)
        finally:
            set_active_socket(None)
        self.assertIsNone(get_active_socket())


if __name__ == "__main__":
    unittest.main()
