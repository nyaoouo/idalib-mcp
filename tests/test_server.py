from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from idalib_mcp.server import (
    _bound_instance_ui_url,
    _enable_path_database_auto_open,
    _instance_ui_url,
    _prefer_management_tools_in_tool_list,
    _save_session_before_close,
    _serve_stdio_instance_ui,
)


class FakeMcp:
    class _Registry:
        def __init__(self):
            self.dispatch = lambda req: None

    def __init__(self) -> None:
        self._http_server: FakeHttpServer | None = None
        self.fail_ports: set[int] = set()
        self.serve_calls: list[tuple[str, int, bool, type]] = []
        self.registry = self._Registry()

    def _mcp_tools_list(self) -> dict[str, Any]:
        return {
            "tools": [
                {"name": "idalib_open"},
                {"name": "idalib_list"},
            ]
        }

    def serve(self, *, host: str, port: int, background: bool, request_handler: type) -> None:
        self.serve_calls.append((host, port, background, request_handler))
        if port in self.fail_ports:
            raise OSError("address already in use")
        bound_port = 18745 if port == 0 else port
        self._http_server = FakeHttpServer(host, bound_port)


class FakeHttpServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 18745) -> None:
        self.server_address = (host, port)


class FakeSession:
    def __init__(self, backend: str = "") -> None:
        self.backend = backend
        self.session_id = ""


class FakeSupervisor:
    def __init__(self) -> None:
        from idalib_mcp.cancellation import CancellationRegistry
        self.opened: tuple[str, str] | None = None
        self.forwarded: tuple[str, dict[str, Any]] | None = None
        self.sessions: dict[str, FakeSession] = {}
        self.saved: tuple[FakeSession, str, dict[str, Any]] | None = None
        self.save_result: dict[str, Any] = {"ok": True, "path": "sample.i64"}
        self._cancels = CancellationRegistry()

    def worker_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": "decompile"},
            {"name": "idalib_open"},
        ]

    def resolve_session(self, database: str | None) -> Any:
        if database in self.sessions:
            return self.sessions[database]
        if database == "existing-session":
            return "existing-session"
        raise KeyError(database)

    def resolve_context_id(self) -> str:
        return "context-id"

    def open_session(self, input_path: str, *, context_id: str) -> str:
        self.opened = (input_path, context_id)
        return "opened-session"

    def forward_raw(self, session: str, request: dict[str, Any]) -> dict[str, Any]:
        self.forwarded = (session, request)
        return {"ok": True}

    def call_worker_tool(self, session: FakeSession, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.saved = (session, tool_name, arguments)
        return self.save_result


class FakeIdalibSupervisor:
    """Minimal base class that mimics upstream.IdalibSupervisor for tests."""

    def __init__(self, *args, isolated_contexts: bool = False, max_workers: int = 4, **kwargs):
        import threading
        self._lock = threading.RLock()
        self.isolated_contexts = isolated_contexts
        self.max_workers = max_workers
        self.sessions: dict = {}
        self.worker_args = list(kwargs.get("worker_args") or [])
        self._tools_cache: dict = {}

    def close_session(self, session_id):
        return False

    def _worker_request_path(self):
        return "/mcp"

    def forward_raw(self, worker, request_obj):
        return self._worker_rpc(worker, request_obj)

    def _worker_rpc(self, worker, request_obj, *, timeout=None):
        raise NotImplementedError


class FakeUpstream:
    IDALIB_MANAGEMENT_TOOLS = {"idalib_open", "idalib_list"}
    IDALIB_HIDDEN_PLUGIN_TOOLS = {"jump_to_address"}

    IdalibSupervisor = FakeIdalibSupervisor

    def __init__(self) -> None:
        self.mcp = FakeMcp()
        self.supervisor = FakeSupervisor()
        self._original_dispatch_called = False

    def _require_supervisor(self) -> FakeSupervisor:
        return self.supervisor

    def _jsonrpc_result(self, request_id: int, result: Any) -> dict[str, Any]:
        return {"id": request_id, "result": result}

    def _call_tool_result(self, payload: Any, *, is_error: bool = False) -> dict[str, Any]:
        return {"payload": payload, "is_error": is_error}

    def _original_dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        self._original_dispatch_called = True
        return {"dispatched": request}


class ServerIntegrationPatchTests(unittest.TestCase):
    def test_instance_ui_url_uses_bound_http_address(self) -> None:
        mcp = FakeMcp()
        mcp._http_server = FakeHttpServer()

        self.assertEqual(_instance_ui_url("127.0.0.1", 8745), "http://127.0.0.1:8745/instances")
        self.assertEqual(_instance_ui_url("::1", 8745), "http://[::1]:8745/instances")
        self.assertEqual(_bound_instance_ui_url(mcp, "localhost", 0), "http://127.0.0.1:18745/instances")

    def test_stdio_instance_ui_retries_with_ephemeral_port(self) -> None:
        upstream = FakeUpstream()
        upstream.mcp.fail_ports.add(8745)

        with self.assertLogs("idalib_mcp.server", level="WARNING"):
            url = _serve_stdio_instance_ui(upstream, "127.0.0.1", 8745, FakeHttpServer)

        self.assertEqual(url, "http://127.0.0.1:18745/instances")
        self.assertEqual([call[1] for call in upstream.mcp.serve_calls], [8745, 0])
        self.assertTrue(all(call[2] for call in upstream.mcp.serve_calls))

    def test_management_tools_are_listed_before_worker_tools(self) -> None:
        upstream = FakeUpstream()

        _prefer_management_tools_in_tool_list(upstream)
        result = upstream._handle_tools_list({"id": 1})

        self.assertEqual(
            [tool["name"] for tool in result["result"]["tools"]],
            ["idalib_open", "idalib_list", "decompile"],
        )

    def test_save_session_before_close_uses_worker_save_tool(self) -> None:
        supervisor = FakeSupervisor()
        session = FakeSession("worker")
        supervisor.sessions["sample"] = session

        result = _save_session_before_close(supervisor, "sample")

        self.assertEqual(result, {"ok": True, "path": "sample.i64"})
        self.assertEqual(supervisor.saved, (session, "idalib_save", {"path": ""}))

    def test_save_session_before_close_uses_gui_save_tool(self) -> None:
        supervisor = FakeSupervisor()
        session = FakeSession("gui")
        supervisor.sessions["sample"] = session

        _save_session_before_close(supervisor, "sample")

        self.assertEqual(supervisor.saved, (session, "idb_save", {"path": ""}))

    def test_analysis_call_auto_opens_existing_database_path(self) -> None:
        upstream = FakeUpstream()
        _enable_path_database_auto_open(upstream)

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "sample.exe"
            input_path.write_bytes(b"MZ")

            result = upstream._handle_tools_call(
                {
                    "id": 7,
                    "params": {
                        "name": "decompile",
                        "arguments": {
                            "database": str(input_path),
                            "addr": "0x401000",
                        },
                    },
                }
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(upstream.supervisor.opened, (str(input_path), "context-id"))
        self.assertIsNotNone(upstream.supervisor.forwarded)
        session, forwarded = upstream.supervisor.forwarded
        self.assertEqual(session, "opened-session")
        self.assertEqual(forwarded["params"]["arguments"], {"addr": "0x401000"})


class SupervisorDispatcherIntegrationTests(unittest.TestCase):
    def _build_supervisor(self):
        from idalib_mcp.server import _build_managed_supervisor_class

        upstream = FakeUpstream()
        cls = _build_managed_supervisor_class(upstream)
        supervisor = cls(FakeMcp(), worker_args=[])
        return supervisor

    def test_get_or_create_dispatcher_returns_same_instance(self) -> None:
        supervisor = self._build_supervisor()
        d1 = supervisor.get_or_create_dispatcher("session-a")
        d2 = supervisor.get_or_create_dispatcher("session-a")
        self.assertIs(d1, d2)

    def test_close_session_drops_dispatcher(self) -> None:
        supervisor = self._build_supervisor()
        supervisor.get_or_create_dispatcher("session-a")
        # close_session calls super().close_session which uses sessions dict;
        # FakeUpstream has no session 'session-a', so close returns False.
        supervisor.close_session("session-a")
        # The override must still drop the dispatcher entry.
        self.assertNotIn("session-a", supervisor._dispatchers)

    def test_call_worker_rpc_with_cancel_aborts_on_event(self) -> None:
        import http.server, socketserver, threading as th, time

        supervisor = self._build_supervisor()

        # Spin up a tiny HTTP server that sleeps so we can cancel it mid-call.
        class SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                import time as _t
                _t.sleep(2.0)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"jsonrpc":"2.0","result":{},"id":1}')

            def log_message(self, *args, **kwargs):
                pass

        class QuietTCPServer(socketserver.TCPServer):
            def handle_error(self, request, client_address):
                pass

        srv = QuietTCPServer(("127.0.0.1", 0), SlowHandler)
        port = srv.server_address[1]
        srv_thread = th.Thread(target=srv.serve_forever, daemon=True)
        srv_thread.start()

        class FakeWorker:
            host = "127.0.0.1"

        worker = FakeWorker()
        worker.port = port

        cancel = th.Event()
        th.Timer(0.2, cancel.set).start()

        from idalib_mcp.dispatcher import CancelledError
        try:
            t0 = time.monotonic()
            with self.assertRaises(CancelledError):
                supervisor._call_worker_rpc_with_cancel(
                    worker,
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "noop", "arguments": {}}},
                    cancel,
                )
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 1.5, "should abort well before the 2s server sleep")
        finally:
            srv.shutdown()
            srv.server_close()


    def test_forward_raw_routes_tools_call_through_dispatcher(self) -> None:
        supervisor = self._build_supervisor()

        session = FakeSession()
        session.session_id = "session-a"

        captured: list[dict] = []

        def fake_rpc(worker, request_obj, cancel_event):
            captured.append(request_obj)
            return {"jsonrpc": "2.0", "id": request_obj.get("id"),
                    "result": {"content": [], "isError": False, "structuredContent": {"ok": True}}}

        supervisor._call_worker_rpc_with_cancel = fake_rpc

        response = supervisor.forward_raw(session, {
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "decompile", "arguments": {"addr": "0x1000"}},
        })

        self.assertEqual(response["id"], 7)
        self.assertFalse(response["result"]["isError"])
        snapshot = supervisor.get_or_create_dispatcher("session-a").snapshot()
        self.assertEqual(len(snapshot["history"]), 1)
        self.assertEqual(snapshot["history"][0]["tool"], "decompile")

    def test_forward_raw_bypasses_dispatcher_for_non_tools_call(self) -> None:
        supervisor = self._build_supervisor()
        session = FakeSession()
        session.session_id = "session-a"

        # Replace the base _worker_rpc to confirm bypass.
        def base_rpc(worker, request_obj, *, timeout=None):
            return {"jsonrpc": "2.0", "id": request_obj.get("id"), "result": {"ok": True}}

        supervisor._worker_rpc = base_rpc  # type: ignore[assignment]

        response = supervisor.forward_raw(session, {
            "jsonrpc": "2.0", "id": 9, "method": "resources/list", "params": {},
        })
        self.assertEqual(response["result"], {"ok": True})
        # Dispatcher should not have been created for resources/list.
        self.assertNotIn("session-a", supervisor._dispatchers)

    def test_error_response_is_decorated_with_tool_schema(self) -> None:
        supervisor = self._build_supervisor()

        # Seed the cache the supervisor reads schemas from.
        supervisor._tools_cache[()] = [{
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr"],
            },
        }]

        response = {
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": "bad args"}],
                       "isError": True, "structuredContent": {}},
        }

        decorated = supervisor._decorate_error("decompile", response)
        meta = decorated["result"].get("_meta") or {}
        self.assertEqual(meta.get("tool_schema", {}).get("required"), ["addr"])
        texts = [c.get("text", "") for c in decorated["result"]["content"]]
        self.assertTrue(any("Tool schema" in t for t in texts))


class OpenUiToolTests(unittest.TestCase):
    def test_register_open_ui_tool_adds_to_management_set(self) -> None:
        from idalib_mcp.server import _register_open_ui_tool

        upstream = FakeUpstream()
        upstream.IDALIB_MANAGEMENT_TOOLS = set(upstream.IDALIB_MANAGEMENT_TOOLS)

        captured = {}

        class FakeMcpWithTool(FakeMcp):
            def tool(self, func):
                captured["func"] = func
                return func

        upstream.mcp = FakeMcpWithTool()
        _register_open_ui_tool(upstream, host="127.0.0.1", port=8745)

        self.assertIn("idalib_open_ui", upstream.IDALIB_MANAGEMENT_TOOLS)
        result = captured["func"]()
        self.assertEqual(result["url"], "http://127.0.0.1:8745/instances")


class HistoryEndpointTests(unittest.TestCase):
    def _build_handler_and_dispatcher(self):
        from idalib_mcp.dispatcher import WorkerDispatcher
        from idalib_mcp.server import _build_request_handler

        dispatcher = WorkerDispatcher("session-a")
        dispatcher.run("ping", 1, {"x": 1}, lambda _c: {"ok": True}, threading.Event())
        big = "a" * 5000
        dispatcher.run("big", 2, {"blob": big}, lambda _c: {"blob": big}, threading.Event())

        class Supervisor(FakeSupervisor):
            def __init__(self):
                super().__init__()
                self._dispatchers = {"session-a": dispatcher}

        # Minimal base handler so _build_request_handler can subclass it.
        class _FakeMcpHttpRequestHandler:
            pass

        def _fake_serve():
            pass

        _fake_serve.__globals__["McpHttpRequestHandler"] = _FakeMcpHttpRequestHandler  # type: ignore[attr-defined]

        class _FakeMcpServer:
            serve = _fake_serve

        class UpstreamWithSupervisor(FakeUpstream):
            McpServer = _FakeMcpServer
            supervisor = None

        upstream = UpstreamWithSupervisor()
        upstream.supervisor = Supervisor()
        handler_cls = _build_request_handler(upstream)
        return handler_cls, dispatcher, upstream

    def test_history_snapshot_endpoint(self):
        handler_cls, dispatcher, upstream = self._build_handler_and_dispatcher()
        # Bypass network: directly call the routing helper.
        snapshot = handler_cls._history_snapshot(upstream.supervisor, "session-a")
        self.assertEqual(len(snapshot["history"]), 2)

    def test_history_payload_returns_full_text(self):
        handler_cls, dispatcher, upstream = self._build_handler_and_dispatcher()
        big_record = next(r for r in dispatcher.snapshot()["history"] if r["tool"] == "big")
        payload_id = big_record["args_full_id"]
        result = handler_cls._history_payload(
            upstream.supervisor, "session-a", payload_id,
        )
        self.assertIn("a" * 100, result)

    def test_history_payload_returns_none_when_unknown(self):
        handler_cls, dispatcher, upstream = self._build_handler_and_dispatcher()
        result = handler_cls._history_payload(
            upstream.supervisor, "session-a", "unknown.args",
        )
        self.assertIsNone(result)


class CancellationPatchTests(unittest.TestCase):
    def _build_supervisor(self):
        from idalib_mcp.server import _build_managed_supervisor_class
        upstream = FakeUpstream()
        cls = _build_managed_supervisor_class(upstream)
        return upstream, cls(FakeMcp(), worker_args=[])

    def test_notifications_cancelled_sets_event(self):
        from idalib_mcp.server import _wrap_dispatch_supervisor
        upstream, supervisor = self._build_supervisor()
        upstream.supervisor = supervisor
        original_dispatch_calls: list[dict] = []
        upstream._original_dispatch = lambda req: original_dispatch_calls.append(req) or None
        # Seed mcp.registry.dispatch as a callable; _wrap_dispatch_supervisor wraps it.
        upstream.mcp.registry.dispatch = lambda req: None
        _wrap_dispatch_supervisor(upstream)

        handle = supervisor._cancels.register(42)
        # Fire notifications/cancelled and confirm the event sets.
        response = upstream.mcp.registry.dispatch({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 42},
        })
        self.assertIsNone(response)
        self.assertTrue(handle.event.is_set())


if __name__ == "__main__":
    unittest.main()
