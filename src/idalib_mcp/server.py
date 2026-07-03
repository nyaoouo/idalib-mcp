from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .cancellation import CancellationRegistry
from .config import default_ida_home_from_env, validate_ida_home
from .dispatcher import CancelledError, WorkerDispatcher
from .installer import list_available_clients, print_mcp_config, run_install_command


logger = logging.getLogger(__name__)


def _load_upstream_supervisor() -> Any:
    try:
        return importlib.import_module("ida_pro_mcp.idalib_supervisor")
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency 'ida-pro-mcp'. Install this project with "
            "`pip install -e .` before running the supervisor."
        ) from exc


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _build_managed_supervisor_class(upstream):
    class ManagedIdalibSupervisor(upstream.IdalibSupervisor):  # type: ignore[misc]
        def __init__(self, *args, ida_home: Path | None = None, show_worker_io: bool = False, **kwargs):
            self.isolated_contexts = kwargs.pop('isolated_contexts', False)
            super().__init__(*args, **kwargs)
            self.ida_home = ida_home
            self.show_worker_io = show_worker_io
            self._dispatchers: dict[str, WorkerDispatcher] = {}
            self._cancels = CancellationRegistry()
            self._last_user_activity: dict[str, float] = {}
            self._last_auto_save: dict[str, float] = {}
            self._start_auto_save_heartbeat()

        def _start_auto_save_heartbeat(self) -> None:
            import time as _time

            def _beat() -> None:
                while True:
                    threading.Event().wait(20)
                    sessions = getattr(self, "sessions", {})
                    for _sid, _sess in list(sessions.items()):
                        try:
                            if getattr(_sess, "backend", "") != "worker":
                                continue
                            if not _sess.is_alive():
                                self._last_user_activity.pop(_sid, None)
                                self._last_auto_save.pop(_sid, None)
                                continue
                            _user_act = self._last_user_activity.get(_sid, 0)
                            _last_save = self._last_auto_save.get(_sid, 0)
                            if _time.time() - _user_act >= 20 and _user_act > _last_save:
                                _path = str(Path(_sess.input_path).with_suffix(".i64"))
                                self.call_worker_tool(_sess, "idb_save", {"path": _path})
                                self._last_auto_save[_sid] = _time.time()
                        except Exception:
                            pass

            t = threading.Thread(target=_beat, daemon=True, name="auto-save")
            t.start()

        def get_or_create_dispatcher(self, session_id: str) -> WorkerDispatcher:
            with self._lock:
                dispatcher = self._dispatchers.get(session_id)
                if dispatcher is None:
                    dispatcher = WorkerDispatcher(session_id)
                    self._dispatchers[session_id] = dispatcher
                return dispatcher

        def close_session(self, session_id: str) -> bool:
            try:
                session = self.resolve_session(session_id)
                self._discard_opened_worker_session(session)
                return True
            except Exception:
                return False
            finally:
                with self._lock:
                    self._dispatchers.pop(session_id, None)
                self._last_user_activity.pop(session_id, None)
                self._last_auto_save.pop(session_id, None)

        _RPC_CANCEL_POLL_TIMEOUT = 0.5

        def _call_worker_rpc_with_cancel(
            self,
            worker: Any,
            request_obj: dict[str, Any],
            cancel_event: threading.Event,
        ) -> dict[str, Any]:
            import http.client
            import socket as _socket
            body = json.dumps(request_obj).encode("utf-8")
            path = self._worker_request_path()
            conn = http.client.HTTPConnection(
                worker.host, worker.port, timeout=self._RPC_CANCEL_POLL_TIMEOUT
            )
            try:
                if cancel_event.is_set():
                    raise CancelledError("Cancelled before request")
                try:
                    conn.request(
                        "POST", path, body,
                        {"Content-Type": "application/json",
                         "Accept": "application/json, text/event-stream"},
                    )
                except (ConnectionError, OSError, http.client.RemoteDisconnected, http.client.BadStatusLine):
                    if cancel_event.is_set():
                        raise CancelledError("Cancelled during request")
                    raise
                while True:
                    if cancel_event.is_set():
                        raise CancelledError("Cancelled before response")
                    try:
                        response = conn.getresponse()
                        break
                    except (_socket.timeout, TimeoutError):
                        if cancel_event.is_set():
                            raise CancelledError("Request cancelled mid-flight")
                    except (ConnectionError, OSError, http.client.RemoteDisconnected, http.client.BadStatusLine):
                        if cancel_event.is_set():
                            raise CancelledError("Request cancelled mid-flight")
                        raise
                raw_parts: list[bytes] = []
                while True:
                    if cancel_event.is_set():
                        raise CancelledError("Cancelled during read")
                    try:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        raw_parts.append(chunk)
                    except (_socket.timeout, TimeoutError):
                        if cancel_event.is_set():
                            raise CancelledError("Request cancelled mid-flight")
                    except (ConnectionError, OSError, http.client.RemoteDisconnected, http.client.BadStatusLine):
                        if cancel_event.is_set():
                            raise CancelledError("Request cancelled mid-flight")
                        raise
                raw = b"".join(raw_parts).decode("utf-8")
                if response.status >= 400:
                    raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw}")
                return json.loads(raw)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        def forward_raw(self, worker: Any, request_obj: dict[str, Any]) -> dict[str, Any]:
            method = request_obj.get("method")
            if method != "tools/call":
                return super().forward_raw(worker, request_obj)

            params = request_obj.get("params") or {}
            tool_name = params.get("name", "")
            # Track real user activity (exclude auto-save itself)
            import time as _time
            if tool_name != "idb_save":
                sid = getattr(worker, "session_id", "")
                self._last_user_activity[sid] = _time.time()
            arguments = params.get("arguments") or {}
            json_rpc_id = request_obj.get("id")
            cancel_event = self._current_cancel_event(json_rpc_id)
            dispatcher = self.get_or_create_dispatcher(worker.session_id)

            def closure(event: threading.Event) -> dict[str, Any]:
                return self._call_worker_rpc_with_cancel(worker, request_obj, event)

            response = dispatcher.run(tool_name, json_rpc_id, arguments, closure, cancel_event)
            return self._decorate_error(tool_name, response)

        def _current_cancel_event(self, request_id: Any) -> threading.Event:
            with self._cancels._lock:  # noqa: SLF001
                handle = self._cancels._handles.get(request_id)
            return handle.event if handle is not None else threading.Event()

        def _decorate_error(self, tool_name: str, response: dict[str, Any]) -> dict[str, Any]:
            result = response.get("result")
            if not isinstance(result, dict) or not result.get("isError"):
                return response
            schema = self._find_tool_schema(tool_name)
            if schema is None:
                return response
            content = list(result.get("content") or [])
            content.append({
                "type": "text",
                "text": "Tool schema:\n" + json.dumps(schema, indent=2),
            })
            result["content"] = content
            meta = dict(result.get("_meta") or {})
            meta["tool_schema"] = schema
            result["_meta"] = meta
            return response

        def _find_tool_schema(self, tool_name: str) -> dict[str, Any] | None:
            with self._lock:
                caches = list(self._tools_cache.values())
            for tools in caches:
                for tool in tools:
                    if tool.get("name") == tool_name:
                        return tool.get("inputSchema")
            return None

        def _spawn_worker(self):
            port = self._pick_port()
            cmd = [
                sys.executable,
                "-m",
                "idalib_mcp.worker",
            ]
            if self.ida_home is not None:
                cmd.extend(["--ida-home", str(self.ida_home)])
            cmd.extend(
                [
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    *self.worker_args,
                ]
            )

            logger.info("Spawning idalib worker on 127.0.0.1:%d", port)
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=None if self.show_worker_io else subprocess.DEVNULL,
                stderr=None if self.show_worker_io else subprocess.DEVNULL,
                env=os.environ.copy(),
            )
            worker = upstream.WorkerSession(
                session_id=f"__worker_schema_{uuid.uuid4().hex[:8]}",
                input_path="",
                filename="",
                host="127.0.0.1",
                port=port,
                process=process,
                backend="worker",
                owned=True,
                pid=process.pid,
            )
            try:
                self._wait_worker_ready(worker)
            except Exception:
                self._terminate_worker(worker)
                raise
            return worker

    return ManagedIdalibSupervisor


def _snapshot_instances(supervisor: Any) -> dict[str, Any]:
    lock = getattr(supervisor, "_lock", threading.Lock())
    with lock:
        context_bindings = getattr(supervisor, "context_bindings", {})
        binding_counts: dict[str, int] = {}
        for session_id in context_bindings.values():
            binding_counts[session_id] = binding_counts.get(session_id, 0) + 1

        sessions_dict = getattr(supervisor, "sessions", {})
        sessions = [
            session.to_list_dict()
            for session in sessions_dict.values()
        ]

        owned_workers = sum(
            1
            for session in sessions_dict.values()
            if session.backend == "worker" and session.owned and session.is_alive()
        )

        return {
            "sessions": sessions,
            "count": len(sessions),
            "owned_workers": owned_workers,
            "max_workers": getattr(supervisor, "max_workers", 0),
            "isolated_contexts": getattr(supervisor, "isolated_contexts", False),
            "ida_home": str(getattr(supervisor, "ida_home", "")) or None,
        }


def _save_session_before_close(supervisor: Any, session_id: str) -> dict[str, Any]:
    session = supervisor.resolve_session(session_id)
    tool_name = "idb_save"
    save_path = str(Path(session.input_path).with_suffix(".i64"))
    result = supervisor.call_worker_tool(session, tool_name, {"path": save_path})
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected save result")
    if not result.get("ok"):
        error = result.get("error") or "Save failed"
        raise RuntimeError(str(error))
    return result


def _cleanup_loose_db_files(i64_path: str, delete_i64: bool = False) -> None:
    """Remove scattered .id0/.id1/.id2/.nam/.til loose files, and optionally the .i64."""
    if not i64_path or not i64_path.endswith(".i64"):
        return
    base = i64_path[:-4]  # strip .i64
    for ext in (".id0", ".id1", ".id2", ".nam", ".til"):
        try:
            os.remove(base + ext)
        except OSError:
            pass
    if delete_i64:
        try:
            os.remove(i64_path)
        except OSError:
            pass





def _build_request_handler(upstream):
    mcp_http_handler = upstream.McpServer.serve.__globals__["McpHttpRequestHandler"]

    class ManagementHttpRequestHandler(mcp_http_handler):  # type: ignore[misc, valid-type]
        @staticmethod
        def _history_snapshot(supervisor, session_id: str):
            dispatcher = supervisor._dispatchers.get(session_id)
            if dispatcher is None:
                return None
            return dispatcher.snapshot()

        @staticmethod
        def _history_payload(supervisor, session_id: str, payload_id: str):
            dispatcher = supervisor._dispatchers.get(session_id)
            if dispatcher is None:
                return None
            return dispatcher.get_payload(payload_id)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/instances"}:
                if not self._check_api_request():
                    return
                self._send_html(200, self._instances_html())
                return
            if parsed.path == "/api/instances":
                if not self._check_api_request():
                    return
                try:
                    self._send_json(200, _snapshot_instances(self._supervisor()))
                except Exception as exc:
                    self._send_json(500, {"error": str(exc), "type": type(exc).__name__})
                return

            history_match = re.match(r"^/api/instances/([^/]+)/history$", parsed.path)
            if history_match:
                if not self._check_api_request():
                    return
                try:
                    session_id = unquote(history_match.group(1))
                    snapshot = self._history_snapshot(self._supervisor(), session_id)
                    if snapshot is None:
                        self._send_json(200, {"current": None, "queued": [], "history": []})
                        return
                    self._send_json(200, snapshot)
                except Exception as exc:
                    self._send_json(500, {"error": str(exc), "type": type(exc).__name__})
                return

            payload_match = re.match(r"^/api/instances/([^/]+)/history/([^/]+)$", parsed.path)
            if payload_match:
                if not self._check_api_request():
                    return
                try:
                    session_id = unquote(payload_match.group(1))
                    payload_id = unquote(payload_match.group(2))
                    payload = self._history_payload(self._supervisor(), session_id, payload_id)
                    if payload is None:
                        self._send_json(404, {"error": "Payload not found or evicted"})
                        return
                    body = payload.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as exc:
                    self._send_json(500, {"error": str(exc), "type": type(exc).__name__})
                return

            super().do_GET()

        def do_POST(self):
            from .cancellation import set_active_socket
            set_active_socket(self.connection)
            try:
                self._do_POST_inner()
            finally:
                set_active_socket(None)

        def _do_POST_inner(self):
            parsed = urlparse(self.path)
            prefix = "/api/instances/"
            suffix = "/close"
            if parsed.path.startswith(prefix) and parsed.path.endswith(suffix):
                if not self._check_api_request():
                    return
                session_id = unquote(parsed.path[len(prefix) : -len(suffix)])
                if not session_id:
                    self._send_json(400, {"success": False, "error": "Missing session id"})
                    return
                supervisor = self._supervisor()
                options = self._read_json_body()
                save_requested = bool(options.get("save"))
                save_result = None
                cleanup_path = ""
                if save_requested:
                    try:
                        save_result = _save_session_before_close(supervisor, session_id)
                        cleanup_path = save_result.get("path", "")
                    except KeyError:
                        self._send_json(404, {"success": False, "error": f"Session not found: {session_id}"})
                        return
                    except Exception as exc:
                        self._send_json(
                            500,
                            {
                                "success": False,
                                "saved": False,
                                "error": f"Save failed: {exc}",
                            },
                        )
                        return
                else:
                    try:
                        session = supervisor.resolve_session(session_id)
                        cleanup_path = str(Path(session.input_path).with_suffix(".i64"))
                    except Exception:
                        pass
                try:
                    closed = supervisor.close_session(session_id)
                except Exception as exc:
                    self._send_json(500, {"success": False, "error": str(exc)})
                    return
                if closed:
                    _cleanup_loose_db_files(cleanup_path, delete_i64=not save_requested)
                status = 200 if closed else 404
                self._send_json(
                    status,
                    {
                        "success": bool(closed),
                        "saved": bool(save_result),
                        "save_result": save_result,
                        "message": f"Session closed: {session_id}" if closed else None,
                        "error": None if closed else f"Session not found: {session_id}",
                    },
                )
                return
            save_suffix = "/save"
            if parsed.path.startswith(prefix) and parsed.path.endswith(save_suffix):
                if not self._check_api_request():
                    return
                session_id = unquote(parsed.path[len(prefix) : -len(save_suffix)])
                if not session_id:
                    self._send_json(400, {"ok": False, "error": "Missing session id"})
                    return
                try:
                    result = _save_session_before_close(self._supervisor(), session_id)
                    self._send_json(200, {"ok": True, "path": result.get("path", "")})
                except KeyError:
                    self._send_json(404, {"ok": False, "error": f"Session not found: {session_id}"})
                except Exception as exc:
                    self._send_json(500, {"ok": False, "error": str(exc)})
                return
            super().do_POST()

        def _supervisor(self):
            if upstream.supervisor is None:
                raise RuntimeError("idalib supervisor is not initialized")
            return upstream.supervisor

        def _send_json(self, status: int, payload: Any) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            body = self.rfile.read(length)
            if not body:
                return {}
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {}
            return payload if isinstance(payload, dict) else {}

        def _send_html(self, status: int, text: str) -> None:
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _instances_html(self) -> str:
            return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>idalib MCP Instances</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #1d2433;
      --muted: #637083;
      --line: #d8dde6;
      --accent: #0f766e;
      --danger: #b42318;
      --danger-bg: #fff0ee;
      --ok-bg: #ecfdf3;
      --warn-bg: #fff8e6;
      --shadow: rgba(15, 23, 42, 0.08);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #111318;
        --panel: #181c23;
        --text: #edf1f7;
        --muted: #9aa6b5;
        --line: #303744;
        --accent: #2dd4bf;
        --danger: #ff8a80;
        --danger-bg: #351c1a;
        --ok-bg: #123428;
        --warn-bg: #352b16;
        --shadow: rgba(0, 0, 0, 0.25);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", system-ui, sans-serif;
      font-size: 14px;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 16px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1 { margin: 0; font-size: 18px; font-weight: 650; }
    main { padding: 20px 24px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      box-shadow: 0 1px 2px var(--shadow);
      min-height: 72px;
    }
    .metric span { display: block; color: var(--muted); font-size: 12px; }
    .metric strong { display: block; margin-top: 6px; font-size: 20px; }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .status { color: var(--muted); font-size: 13px; }
    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      min-height: 32px;
      padding: 0 12px;
      cursor: pointer;
      font: inherit;
    }
    button:hover { border-color: var(--accent); }
    button.danger { color: var(--danger); background: var(--danger-bg); }
    button:disabled { cursor: not-allowed; opacity: 0.55; }
    .table-wrap {
      overflow-x: auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px var(--shadow);
    }
    table { width: 100%; border-collapse: collapse; min-width: 900px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
    th { color: var(--muted); font-size: 12px; font-weight: 650; background: color-mix(in srgb, var(--panel), var(--bg) 45%); }
    tr:last-child td { border-bottom: 0; }
    code { font-family: Consolas, "SFMono-Regular", monospace; font-size: 12px; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 0 8px;
      border-radius: 999px;
      font-size: 12px;
      background: var(--warn-bg);
      color: var(--text);
      white-space: nowrap;
    }
    .pill.ok { background: var(--ok-bg); }
    .empty { padding: 28px; color: var(--muted); text-align: center; }
    .path { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .modal-backdrop {
            position: fixed;
            inset: 0;
            display: grid;
            place-items: center;
            padding: 20px;
            background: rgba(0, 0, 0, 0.36);
            z-index: 10;
        }
        .modal-backdrop[hidden] { display: none; }
        .modal {
            width: min(420px, 100%);
            border: 1px solid var(--line);
            border-radius: 8px;
            background: var(--panel);
            box-shadow: 0 16px 40px var(--shadow);
            padding: 18px;
        }
        .modal h2 { margin: 0 0 8px; font-size: 16px; }
        .modal p { margin: 0 0 16px; color: var(--muted); line-height: 1.4; }
        .modal-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
  </style>
</head>
<body>
  <header>
    <h1>idalib MCP Instances</h1>
    <button id="refresh" title="Refresh instance list">Refresh</button>
  </header>
  <main>
    <section class="summary" aria-label="Summary">
      <div class="metric"><span>Instances</span><strong id="count">0</strong></div>
      <div class="metric"><span>Workers</span><strong id="workers">0</strong></div>
      <div class="metric"><span>Limit</span><strong id="limit">0</strong></div>
      <div class="metric"><span>IDA Home</span><strong id="idaHome" style="font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">auto</strong></div>
    </section>
    <div class="toolbar">
      <div class="status" id="status">Loading</div>
    </div>
    <div class="table-wrap">
      <table aria-label="Instances">
        <thead>
          <tr>
            <th>Session</th>
            <th>File</th>
            <th>Backend</th>
            <th>PID</th>
            <th>State</th>
            <th>Bound</th>
            <th>Last Accessed</th>
            <th>Path</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="empty" id="empty" hidden>No instances</div>
    </div>
  </main>
    <div class="modal-backdrop" id="closeDialog" hidden>
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="closeTitle">
            <h2 id="closeTitle">Close Instance</h2>
            <p>Save database changes before closing <code id="closeDialogSession">-</code>?</p>
            <div class="modal-actions">
                <button id="cancelClose">Cancel</button>
                <button class="danger" id="closeWithoutSave">Close without saving</button>
                <button id="saveAndClose">Save and close</button>
            </div>
        </div>
    </div>
    <div class="modal-backdrop" id="inspectDialog" hidden>
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="inspectTitle" style="width:min(720px,100%);max-height:80vh;display:flex;flex-direction:column;">
            <h2 id="inspectTitle">Inspect <code id="inspectSession">-</code></h2>
            <div style="overflow:auto;flex:1;">
                <h3 style="margin:8px 0;font-size:14px;">Current</h3>
                <div id="inspectCurrent" class="empty">Idle</div>
                <h3 style="margin:8px 0;font-size:14px;">Queued (<span id="inspectQueuedCount">0</span>)</h3>
                <div id="inspectQueued" class="empty">No queued requests</div>
                <h3 style="margin:8px 0;font-size:14px;">History (last 100)</h3>
                <div id="inspectHistory" class="empty">No history</div>
            </div>
            <div class="modal-actions">
                <button id="closeInspect">Close</button>
            </div>
        </div>
    </div>
  <script>
    const rows = document.getElementById('rows');
    const empty = document.getElementById('empty');
    const statusEl = document.getElementById('status');
    const refreshButton = document.getElementById('refresh');
        const closeDialog = document.getElementById('closeDialog');
        const closeDialogSession = document.getElementById('closeDialogSession');
        const cancelClose = document.getElementById('cancelClose');
        const closeWithoutSave = document.getElementById('closeWithoutSave');
        const saveAndClose = document.getElementById('saveAndClose');
        let pendingClose = null;

    function text(value) {
      return value === null || value === undefined || value === '' ? '-' : String(value);
    }

    function escapeHtml(value) {
      return text(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[char]));
    }

    function fmtTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }

    function sessionRow(session) {
      const tr = document.createElement('tr');
      const activeClass = session.is_active ? 'pill ok' : 'pill';
      const sessionId = escapeHtml(session.session_id);
      const inputPath = escapeHtml(session.input_path);
      tr.innerHTML = `
        <td><code>${sessionId}</code></td>
        <td>${escapeHtml(session.filename)}</td>
        <td>${escapeHtml(session.backend)}</td>
        <td>${escapeHtml(session.pid ?? session.worker_pid)}</td>
        <td><span class="${activeClass}">${session.is_active ? 'running' : 'stopped'}</span></td>
        <td>${escapeHtml(session.bound_contexts)}</td>
        <td>${escapeHtml(fmtTime(session.last_accessed))}</td>
        <td class="path" title="${inputPath}">${inputPath}</td>
        <td>
          <button data-inspect="${sessionId}">Inspect</button>
          <button data-save="${sessionId}" ${session.is_active && session.owned ? '' : 'disabled'}>Save</button>
          <button class="danger" data-close="${sessionId}" ${session.owned === false ? 'disabled' : ''}>Close</button>
        </td>
      `;
      return tr;
    }

    async function refresh() {
      statusEl.textContent = 'Refreshing';
      const response = await fetch('/api/instances', {cache: 'no-store'});
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      document.getElementById('count').textContent = data.count ?? 0;
      document.getElementById('workers').textContent = data.owned_workers ?? 0;
      document.getElementById('limit').textContent = data.max_workers === 0 ? 'unlimited' : text(data.max_workers);
      document.getElementById('idaHome').textContent = data.ida_home || 'auto';
      rows.replaceChildren(...(data.sessions || []).map(sessionRow));
      empty.hidden = Boolean((data.sessions || []).length);
      statusEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    }

        function showCloseDialog(sessionId, button) {
            pendingClose = {sessionId, button};
            closeDialogSession.textContent = sessionId;
            closeDialog.hidden = false;
            saveAndClose.focus();
        }

        function hideCloseDialog() {
            closeDialog.hidden = true;
            pendingClose = null;
        }

        async function closeSession(sessionId, button, save) {
      button.disabled = true;
            statusEl.textContent = save ? `Saving ${sessionId}` : `Closing ${sessionId}`;
            const response = await fetch(`/api/instances/${encodeURIComponent(sessionId)}/close`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({save})
            });
      if (!response.ok) {
        const body = await response.text();
        throw new Error(body || response.statusText);
      }
      await refresh();
    }

        async function saveSession(sessionId, button) {
      button.disabled = true;
            statusEl.textContent = `Saving ${sessionId}`;
            try {
                const response = await fetch(`/api/instances/${encodeURIComponent(sessionId)}/save`, {
                    method: 'POST'
                });
                if (!response.ok) {
                    const body = await response.text();
                    throw new Error(body || response.statusText);
                }
                const data = await response.json();
                statusEl.textContent = `Saved ${sessionId} → ${data.path || 'ok'}`;
            } catch (error) {
                statusEl.textContent = error.message;
            }
      button.disabled = false;
    }

    rows.addEventListener('click', event => {
      const button = event.target.closest('button[data-close]');
      if (!button) return;
            showCloseDialog(button.dataset.close, button);
        });
        rows.addEventListener('click', event => {
      const button = event.target.closest('button[data-save]');
      if (!button) return;
            saveSession(button.dataset.save, button);
        });
        cancelClose.addEventListener('click', hideCloseDialog);
        closeDialog.addEventListener('click', event => {
            if (event.target === closeDialog) hideCloseDialog();
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !closeDialog.hidden) hideCloseDialog();
        });
        closeWithoutSave.addEventListener('click', () => {
            const request = pendingClose;
            if (!request) return;
            hideCloseDialog();
            closeSession(request.sessionId, request.button, false).catch(error => {
        statusEl.textContent = error.message;
                request.button.disabled = false;
      });
    });
        saveAndClose.addEventListener('click', () => {
            const request = pendingClose;
            if (!request) return;
            hideCloseDialog();
            closeSession(request.sessionId, request.button, true).catch(error => {
                statusEl.textContent = error.message;
                request.button.disabled = false;
            });
        });
    refreshButton.addEventListener('click', () => refresh().catch(error => { statusEl.textContent = error.message; }));
    refresh().catch(error => { statusEl.textContent = error.message; });
    setInterval(() => refresh().catch(error => { statusEl.textContent = error.message; }), 5000);

        const inspectDialog = document.getElementById('inspectDialog');
        const inspectSession = document.getElementById('inspectSession');
        const inspectCurrent = document.getElementById('inspectCurrent');
        const inspectQueued = document.getElementById('inspectQueued');
        const inspectQueuedCount = document.getElementById('inspectQueuedCount');
        const inspectHistory = document.getElementById('inspectHistory');
        const closeInspect = document.getElementById('closeInspect');
        let inspectInterval = null;
        let inspectingSession = null;

        function renderRecord(record) {
            const status = escapeHtml(record.status);
            const tool = escapeHtml(record.tool);
            const duration = record.duration_ms == null ? '-' : `${record.duration_ms.toFixed(1)} ms`;
            const argsPreview = escapeHtml(record.args_preview ?? '');
            const resultPreview = escapeHtml(record.result_preview ?? '');
            const argsLink = record.args_full_id
                ? `<a href="/api/instances/${encodeURIComponent(inspectingSession)}/history/${encodeURIComponent(record.args_full_id)}" target="_blank">view full</a>`
                : '';
            const resultLink = record.result_full_id
                ? `<a href="/api/instances/${encodeURIComponent(inspectingSession)}/history/${encodeURIComponent(record.result_full_id)}" target="_blank">view full</a>`
                : '';
            const errorText = record.error ? `<div style="color:var(--danger);">${escapeHtml(record.error)}</div>` : '';
            return `<div style="padding:8px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px;">
              <div><strong>${tool}</strong> <span class="pill">${status}</span> <span style="color:var(--muted);">${duration}</span></div>
              <div style="margin-top:4px;font-size:12px;">args: <code>${argsPreview}</code> ${argsLink}</div>
              <div style="margin-top:4px;font-size:12px;">result: <code>${resultPreview}</code> ${resultLink}</div>
              ${errorText}
            </div>`;
        }

        async function refreshInspect() {
            if (!inspectingSession) return;
            try {
                const response = await fetch(`/api/instances/${encodeURIComponent(inspectingSession)}/history`, {cache: 'no-store'});
                if (!response.ok) {
                    inspectCurrent.innerHTML = '<div class="empty">No dispatcher for this session yet</div>';
                    inspectQueued.innerHTML = '';
                    inspectHistory.innerHTML = '';
                    inspectQueuedCount.textContent = '0';
                    return;
                }
                const data = await response.json();
                inspectCurrent.innerHTML = data.current ? renderRecord(data.current) : '<div class="empty">Idle</div>';
                inspectQueued.innerHTML = (data.queued || []).map(renderRecord).join('') || '<div class="empty">No queued requests</div>';
                inspectQueuedCount.textContent = (data.queued || []).length;
                inspectHistory.innerHTML = (data.history || []).slice().reverse().map(renderRecord).join('') || '<div class="empty">No history</div>';
            } catch (error) {
                inspectCurrent.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
            }
        }

        function openInspect(sessionId) {
            inspectingSession = sessionId;
            inspectSession.textContent = sessionId;
            inspectDialog.hidden = false;
            refreshInspect();
            inspectInterval = setInterval(refreshInspect, 5000);
        }

        function closeInspectDialog() {
            inspectDialog.hidden = true;
            inspectingSession = null;
            if (inspectInterval) {
                clearInterval(inspectInterval);
                inspectInterval = null;
            }
        }

        rows.addEventListener('click', event => {
            const button = event.target.closest('button[data-inspect]');
            if (!button) return;
            openInspect(button.dataset.inspect);
        });
        closeInspect.addEventListener('click', closeInspectDialog);
        inspectDialog.addEventListener('click', event => {
            if (event.target === inspectDialog) closeInspectDialog();
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !inspectDialog.hidden) closeInspectDialog();
        });
  </script>
</body>
</html>"""

    return ManagementHttpRequestHandler


def _format_url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _instance_ui_url(host: str, port: int) -> str:
    return f"http://{_format_url_host(host)}:{port}/instances"


def _bound_instance_ui_url(mcp: Any, fallback_host: str, fallback_port: int) -> str:
    server = getattr(mcp, "_http_server", None)
    if server is None:
        return _instance_ui_url(fallback_host, fallback_port)

    host, port = server.server_address[:2]
    display_host = fallback_host if host in ("", "0.0.0.0", "::") else str(host)
    return _instance_ui_url(display_host, int(port))


def _serve_stdio_instance_ui(upstream: Any, host: str, port: int, request_handler: type) -> str:
    try:
        upstream.mcp.serve(host=host, port=port, background=True, request_handler=request_handler)
    except OSError as exc:
        if port == 0:
            raise
        logger.warning(
            "Instance UI port %s is unavailable (%s); retrying with an ephemeral port",
            port,
            exc,
        )
        upstream.mcp.serve(host=host, port=0, background=True, request_handler=request_handler)
    return _bound_instance_ui_url(upstream.mcp, host, port)


def _prefer_management_tools_in_tool_list(upstream) -> None:
    def _handle_tools_list_management_first(request_obj: dict[str, Any]) -> dict[str, Any]:
        supervisor = upstream._require_supervisor()
        local_tools = upstream.mcp._mcp_tools_list().get("tools", [])
        local_names = {tool.get("name") for tool in local_tools}
        worker_tools = [
            tool
            for tool in supervisor.worker_tools()
            if tool.get("name") not in local_names
        ]
        return upstream._jsonrpc_result(
            request_obj.get("id"),
            {"tools": local_tools + worker_tools},
        )

    upstream._handle_tools_list = _handle_tools_list_management_first


def _enable_path_database_auto_open(upstream) -> None:
    def _resolve_or_open_path_database(supervisor, database: str | None):
        try:
            return supervisor.resolve_session(database)
        except Exception:
            if not database:
                raise
            candidate = Path(database).expanduser()
            if not candidate.exists():
                raise
            context_id = supervisor.resolve_context_id()
            # Clean up orphan loose files from a previous unclean shutdown
            _cleanup_loose_db_files(str(candidate.with_suffix(".i64")))
            return supervisor.open_session(str(candidate), context_id=context_id)

    def _handle_tools_call_with_path_open(request_obj: dict[str, Any]) -> dict[str, Any] | None:
        from .cancellation import get_active_socket, spawn_socket_watcher

        supervisor = upstream._require_supervisor()
        params = request_obj.get("params") or {}
        tool_name = params.get("name", "")
        request_id = request_obj.get("id")

        # Clean up orphan loose files from previous unclean shutdown
        arguments = dict(params.get("arguments") or {})
        _candidate = arguments.get("database") or arguments.get("input_path") or ""
        if _candidate:
            _cleanup_loose_db_files(str(Path(_candidate).with_suffix(".i64")))

        if tool_name in upstream.IDB_MANAGEMENT_TOOLS:
            return upstream._original_dispatch(request_obj)
        if tool_name in getattr(upstream, "IDALIB_HIDDEN_PLUGIN_TOOLS", []):
            return upstream._jsonrpc_result(
                request_id,
                upstream._call_tool_result(
                    {
                        "error": (
                            f"{tool_name} is a GUI-plugin routing tool and is not "
                            "available through idalib-mcp. Use idalib_list or "
                            "idalib_switch instead."
                        )
                    },
                    is_error=True,
                ),
            )

        arguments = dict(params.get("arguments") or {})
        database = arguments.pop("database", None)
        try:
            session = _resolve_or_open_path_database(supervisor, database)
        except Exception as exc:
            return upstream._jsonrpc_result(
                request_id,
                upstream._call_tool_result({"error": str(exc)}, is_error=True),
            )

        forwarded = dict(request_obj)
        forwarded["params"] = dict(params)
        forwarded["params"]["arguments"] = arguments

        handle = supervisor._cancels.register(request_id) if request_id is not None else None
        sock = get_active_socket()
        stop = threading.Event()
        watcher = spawn_socket_watcher(handle, sock, stop) if (handle and sock) else None
        try:
            return supervisor.forward_raw(session, forwarded)
        except CancelledError:
            return upstream._jsonrpc_result(
                request_id,
                upstream._call_tool_result({"error": "Request cancelled"}, is_error=True),
            )
        except Exception as exc:
            return upstream._jsonrpc_result(
                request_id,
                upstream._call_tool_result({"error": str(exc)}, is_error=True),
            )
        finally:
            stop.set()
            if watcher is not None:
                watcher.join(timeout=1.0)
            if handle is not None and request_id is not None:
                supervisor._cancels.unregister(request_id)

    upstream._handle_tools_call = _handle_tools_call_with_path_open


def _register_open_ui_tool(upstream, *, host: str, port: int) -> None:
    def idalib_open_ui() -> dict:
        """Return the bound management UI URL."""
        return {"url": _bound_instance_ui_url(upstream.mcp, host, port)}

    idalib_open_ui.__doc__ = "Return the bound management UI URL."
    upstream.mcp.tool(idalib_open_ui)
    upstream.IDB_MANAGEMENT_TOOLS.add("idalib_open_ui")


def _wrap_dispatch_supervisor(upstream) -> None:
    original = upstream.mcp.registry.dispatch

    def wrapped(request):
        request_obj = request
        if not isinstance(request, dict):
            try:
                request_obj = json.loads(request)
            except Exception:
                request_obj = None
        if isinstance(request_obj, dict) and request_obj.get("method") == "notifications/cancelled":
            params = request_obj.get("params") or {}
            target = params.get("requestId")
            if target is not None and upstream.supervisor is not None:
                upstream.supervisor._cancels.cancel(target)
            return None
        return original(request)

    upstream.mcp.registry.dispatch = wrapped


def main() -> None:
    parser = argparse.ArgumentParser(description="Headless MCP supervisor for IDA Pro via idalib")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install MCP client config entries. Optionally pass comma-separated targets.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Remove MCP client config entries. Optionally pass comma-separated targets.",
    )
    parser.add_argument("--config", action="store_true", help="Print example MCP config JSON")
    parser.add_argument("--list-clients", action="store_true", help="List supported MCP client config targets")
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="For install/config: stdio, streamable-http, sse, or URL. For running: stdio or URL.",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: project (default for explicit targets) or global.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--stdio", action="store_true", help="Serve MCP over stdio instead of HTTP")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8745, help="HTTP port, default: 8745")
    parser.add_argument(
        "--ida-home",
        type=Path,
        default=default_ida_home_from_env(),
        help="IDA installation directory. Overrides idapro config for worker processes.",
    )
    parser.add_argument(
        "--isolated-contexts",
        action="store_true",
        help="Enable strict per-transport database binding isolation.",
    )
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe worker tools, including debugger tools")
    parser.add_argument("--profile", type=Path, default=None, metavar="PATH", help="Restrict worker tools to a profile file")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=int(os.environ.get("IDA_MCP_MAX_WORKERS", "4")),
        help="Maximum simultaneous worker databases (0 = unlimited, default: 4)",
    )
    parser.add_argument(
        "--show-worker-io",
        action="store_true",
        help="Inherit worker stdout/stderr instead of suppressing it",
    )
    parser.add_argument("input_path", type=Path, nargs="?", help="Optional binary to open on startup")
    args = parser.parse_args()

    if args.list_clients:
        list_available_clients()
        return

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None
    if args.scope and not (is_install or is_uninstall):
        raise SystemExit("--scope requires --install or --uninstall")
    if is_install and is_uninstall:
        raise SystemExit("Cannot install and uninstall at the same time")
    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return
    if args.config:
        print_mcp_config(args)
        return

    if args.transport is not None:
        if args.transport == "stdio":
            args.stdio = True
        else:
            transport_url = urlparse(args.transport)
            if transport_url.hostname is None or transport_url.port is None:
                raise SystemExit(f"Invalid transport URL: {args.transport}")
            args.host = transport_url.hostname
            args.port = transport_url.port

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    ida_home = validate_ida_home(args.ida_home) if args.ida_home is not None else None
    upstream = _load_upstream_supervisor()
    managed_supervisor_class = _build_managed_supervisor_class(upstream)

    worker_args: list[str] = []
    if args.verbose:
        worker_args.append("--verbose")
    if args.unsafe:
        worker_args.append("--unsafe")
    if args.profile is not None:
        worker_args.extend(["--profile", str(args.profile)])

    upstream.supervisor = managed_supervisor_class(
        upstream.mcp,
        isolated_contexts=args.isolated_contexts,
        max_workers=args.max_workers,
        worker_args=worker_args,
        ida_home=ida_home,
        show_worker_io=args.show_worker_io,
    )
    _prefer_management_tools_in_tool_list(upstream)
    _enable_path_database_auto_open(upstream)
    _register_open_ui_tool(upstream, host=args.host, port=args.port)
    upstream.mcp.registry.dispatch = upstream.dispatch_supervisor
    _wrap_dispatch_supervisor(upstream)
    upstream.mcp.require_streamable_http_session = args.isolated_contexts

    if args.input_path is not None:
        startup_context_id = (
            upstream.STDIO_DEFAULT_CONTEXT_ID if args.isolated_contexts else upstream.SHARED_FALLBACK_CONTEXT_ID
        )
        try:
            upstream.supervisor.open_session(str(args.input_path), context_id=startup_context_id)
        except Exception as exc:
            raise SystemExit(f"Failed to open initial binary: {exc}") from exc

    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down idalib supervisor")
        if upstream.supervisor is not None:
            upstream.supervisor.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    try:
        handler = _build_request_handler(upstream)
        if args.stdio:
            ui_url = _serve_stdio_instance_ui(upstream, args.host, args.port, handler)
            logger.info("Instance UI: %s", ui_url)
            print(f"Instance UI: {ui_url}", file=sys.stderr, flush=True)
            upstream.mcp.stdio()
        else:
            logger.info("Instance UI: %s", _instance_ui_url(args.host, args.port))
            stop = threading.Event()

            def threaded_cleanup(signum, frame):
                stop.set()

            signal.signal(signal.SIGINT, threaded_cleanup)
            signal.signal(signal.SIGTERM, threaded_cleanup)

            upstream.mcp.serve(
                host=args.host, port=args.port, background=True, request_handler=handler,
            )
            try:
                stop.wait()
            finally:
                upstream.mcp.stop()
    finally:
        if upstream.supervisor is not None:
            upstream.supervisor.shutdown()


if __name__ == "__main__":
    main()
