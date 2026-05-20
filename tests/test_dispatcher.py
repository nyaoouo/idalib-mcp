from __future__ import annotations

import threading
import time
import unittest

from idalib_mcp.dispatcher import WorkerDispatcher


class WorkerDispatcherBasicsTests(unittest.TestCase):
    def test_run_marks_record_ok_and_appends_to_history(self) -> None:
        dispatcher = WorkerDispatcher("session-a")

        result = dispatcher.run(
            tool="ping",
            json_rpc_id=1,
            args={"x": 1},
            fn=lambda cancel_event: {"ok": True},
            cancel_event=threading.Event(),
        )

        self.assertEqual(result, {"ok": True})
        snapshot = dispatcher.snapshot()
        self.assertIsNone(snapshot["current"])
        self.assertEqual(snapshot["queued"], [])
        self.assertEqual(len(snapshot["history"]), 1)
        record = snapshot["history"][0]
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["tool"], "ping")
        self.assertEqual(record["session_id"], "session-a")
        self.assertEqual(record["args_preview"], '{"x":1}')
        self.assertIsNone(record["args_full_id"])
        self.assertEqual(record["result_preview"], '{"ok":true}')
        self.assertGreaterEqual(record["duration_ms"], 0)
        self.assertIsNone(record["error"])

    def test_run_marks_record_error_when_closure_raises(self) -> None:
        dispatcher = WorkerDispatcher("session-a")

        def boom(_cancel_event):
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            dispatcher.run("explode", 1, {}, boom, threading.Event())

        history = dispatcher.snapshot()["history"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "error")
        self.assertEqual(history[0]["error"], "boom")

    def test_history_capped_at_100(self) -> None:
        dispatcher = WorkerDispatcher("s")
        for i in range(150):
            dispatcher.run(
                tool=f"t{i}",
                json_rpc_id=i,
                args={},
                fn=lambda _cancel: {"i": _cancel is None or i},
                cancel_event=threading.Event(),
            )
        snapshot = dispatcher.snapshot()
        self.assertEqual(len(snapshot["history"]), 100)
        self.assertEqual(snapshot["history"][0]["tool"], "t50")
        self.assertEqual(snapshot["history"][-1]["tool"], "t149")

    def test_long_args_and_result_produce_full_payload_ids(self) -> None:
        dispatcher = WorkerDispatcher("s")
        big = "a" * 5000
        dispatcher.run(
            tool="t",
            json_rpc_id=1,
            args={"blob": big},
            fn=lambda _c: {"blob": big},
            cancel_event=threading.Event(),
        )
        record = dispatcher.snapshot()["history"][0]
        self.assertIsNotNone(record["args_full_id"])
        self.assertIsNotNone(record["result_full_id"])
        full_args = dispatcher.get_payload(record["args_full_id"])
        self.assertIn(big, full_args)

    def test_payload_cap_evicts_oldest(self) -> None:
        dispatcher = WorkerDispatcher("s")
        dispatcher.PAYLOAD_CAP = 5
        big = "a" * 5000
        for i in range(dispatcher.PAYLOAD_CAP + 10):
            dispatcher.run(
                tool="t",
                json_rpc_id=i,
                args={"blob": big, "i": i},
                fn=lambda _c: {},
                cancel_event=threading.Event(),
            )
        self.assertLessEqual(len(dispatcher._payloads), dispatcher.PAYLOAD_CAP)
        first_record = dispatcher.snapshot()["history"][0]
        self.assertIsNone(dispatcher.get_payload(first_record["args_full_id"]))


class WorkerDispatcherCancellationTests(unittest.TestCase):
    def test_cancel_before_run_raises_cancelled(self) -> None:
        from idalib_mcp.dispatcher import CancelledError

        dispatcher = WorkerDispatcher("s")
        event = threading.Event()
        event.set()

        with self.assertRaises(CancelledError):
            dispatcher.run(
                tool="t", json_rpc_id=1, args={},
                fn=lambda _c: {"unreachable": True},
                cancel_event=event,
            )

        history = dispatcher.snapshot()["history"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "cancelled")

    def test_cancel_while_queued_unblocks_second_caller(self) -> None:
        from idalib_mcp.dispatcher import CancelledError

        dispatcher = WorkerDispatcher("s")
        first_release = threading.Event()
        first_started = threading.Event()

        def first(_cancel):
            first_started.set()
            first_release.wait(timeout=5)
            return {"ok": True}

        first_event = threading.Event()
        second_event = threading.Event()

        t1 = threading.Thread(
            target=dispatcher.run,
            args=("first", 1, {}, first, first_event),
        )
        t1.start()
        self.assertTrue(first_started.wait(timeout=2))

        outcome: list[BaseException] = []

        def second_call():
            try:
                dispatcher.run("second", 2, {}, lambda _c: {}, second_event)
            except BaseException as exc:
                outcome.append(exc)

        t2 = threading.Thread(target=second_call)
        t2.start()

        # Wait until the second call is registered as queued.
        for _ in range(50):
            if any(r["tool"] == "second" for r in dispatcher.snapshot()["queued"]):
                break
            time.sleep(0.02)
        else:
            self.fail("second call never entered the queue")

        second_event.set()
        t2.join(timeout=2)
        first_release.set()
        t1.join(timeout=2)

        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], CancelledError)
        history = {r["tool"]: r for r in dispatcher.snapshot()["history"]}
        self.assertEqual(history["first"]["status"], "ok")
        self.assertEqual(history["second"]["status"], "cancelled")

    def test_different_dispatchers_run_in_parallel(self) -> None:
        a = WorkerDispatcher("a")
        b = WorkerDispatcher("b")
        barrier = threading.Barrier(2, timeout=2)

        def body(_cancel):
            barrier.wait()
            return {}

        threads = [
            threading.Thread(target=a.run, args=("t", 1, {}, body, threading.Event())),
            threading.Thread(target=b.run, args=("t", 1, {}, body, threading.Event())),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3)
        for t in threads:
            self.assertFalse(t.is_alive(), "thread did not finish — likely serialized")


if __name__ == "__main__":
    unittest.main()
