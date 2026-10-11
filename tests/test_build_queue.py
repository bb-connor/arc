import fcntl
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swarmlib import build


class FairAdmissionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="swarm-queue-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = mock.patch.dict(os.environ, {
            "SWARM_BUILD_DIR": str(self.root / "slots"),
            "SWARM_BUILD_ENV": str(self.root / "no-host.env"),
            "SWARM_BUILD_SLOTS": "2",
            "SWARM_BUILD_CGROUP": "0",
            "SWARM_BUILD_DISK_FLOOR_GB": "0",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.owned = set()
        self.addCleanup(self._release_all)

    def _release_all(self):
        for fd in list(self.owned):
            self._release(fd)

    def _release(self, fd):
        self.owned.remove(fd)
        build.release(fd)

    def _hold_slot(self, slot):
        fd = os.open(build.slot_dir() / f"slot-{slot}.lock", os.O_RDWR | os.O_CREAT, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owned.add(fd)
        return fd

    def _queue(self, build_class="coder"):
        return build.slot_dir() / f"queue-{build_class}"

    def _hold_ticket(self, position, build_class="coder"):
        queue = self._queue(build_class)
        queue.mkdir(exist_ok=True)
        path = queue / f"ticket-{position:020d}-fixture.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owned.add(fd)
        return fd, path

    def _acquire(self, slots, **options):
        fd, slot, waited = build.acquire(slots, **options)
        self.owned.add(fd)
        return fd, slot, waited

    def _assert_locked(self, path):
        fd = os.open(path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def _assert_guard_free(self, build_class="coder"):
        path = self._queue(build_class) / "guard.lock"
        self.assertTrue(path.is_file())
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_older_waiter_has_next_turn_when_younger_polls_first(self):
        occupied = self._hold_slot(0)

        def younger_polls_first(_seconds):
            self._release(occupied)
            # The older acquire is asleep; the younger call sees a free slot.
            with self.assertRaises(TimeoutError):
                self._acquire(1, timeout=0)

        with mock.patch.object(build.time, "sleep", side_effect=younger_polls_first) as sleep:
            _fd, slot, waited = self._acquire(1, poll=1)
        self.assertEqual(slot, 0)
        self.assertGreaterEqual(waited, 0)
        sleep.assert_called_once_with(1)

    def test_stale_ticket_is_pruned_while_live_ticket_keeps_its_turn(self):
        queue = self._queue()
        queue.mkdir()
        stale = queue / "ticket-00000000000000000000-stale.lock"
        stale.write_text("")
        live_fd, live = self._hold_ticket(1)
        with self.assertRaises(TimeoutError):
            self._acquire(1, timeout=0)
        self.assertFalse(stale.exists())
        self.assertTrue(live.exists())
        self._assert_locked(live)
        # Closing the owner FD models kernel lock cleanup after a crash.
        self._release(live_fd)
        _fd, slot, _waited = self._acquire(1, timeout=0)
        self.assertEqual(slot, 0)
        self.assertFalse(live.exists())

    def test_abandoned_younger_ticket_does_not_bypass_live_older_ticket(self):
        older_fd, older = self._hold_ticket(10)
        younger_fd, younger = self._hold_ticket(11)
        self._release(younger_fd)
        with self.assertRaises(TimeoutError):
            self._acquire(1, timeout=0)
        self.assertTrue(older.exists())
        self.assertFalse(younger.exists())
        self._release(older_fd)
        self._acquire(1, timeout=0)
        self.assertFalse(older.exists())

    def test_timeout_removes_ticket_without_releasing_active_build(self):
        self._hold_slot(0)
        with self.assertRaises(TimeoutError):
            self._acquire(1, timeout=0)
        self.assertEqual(list(self._queue().glob("ticket-*.lock")), [])
        self._assert_locked(build.slot_dir() / "slot-0.lock")
        self._assert_guard_free()

    def test_interrupted_wait_removes_ticket_and_releases_queue_guard(self):
        occupied = self._hold_slot(0)
        with mock.patch.object(build.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self._acquire(1)
        self.assertEqual(list(self._queue().glob("ticket-*.lock")), [])
        self._assert_guard_free()
        self._assert_locked(build.slot_dir() / "slot-0.lock")
        self._release(occupied)
        self._acquire(1, timeout=0)

    def test_admitted_builds_leave_the_queue_so_multiple_slots_remain_usable(self):
        first, first_slot, _ = self._acquire([1, 2], timeout=0)
        second, second_slot, _ = self._acquire([1, 2], timeout=0)
        self.assertEqual((first_slot, second_slot), (1, 2))
        self.assertEqual(list(self._queue().glob("ticket-*.lock")), [])
        with self.assertRaises(TimeoutError):
            self._acquire([1, 2], timeout=0)
        self._release(first)
        third, third_slot, _ = self._acquire([1, 2], timeout=0)
        self.assertEqual(third_slot, 1)
        self._assert_locked(build.slot_dir() / "slot-2.lock")
        self._release(second)
        self._release(third)

    def test_integrator_can_use_shared_slot_without_joining_coder_queue(self):
        self._hold_slot(0)
        _ticket_fd, coder = self._hold_ticket(0, "coder")
        with mock.patch.object(build.subprocess, "call", return_value=0), \
                mock.patch.object(build.time, "sleep", side_effect=AssertionError("integrator queued behind coder")):
            self.assertEqual(build.run(["not-executed"], build_class="integrator"), 0)
        record = json.loads((build.slot_dir() / "waits.log").read_text())
        self.assertEqual((record["class"], record["slot"]), ("integrator", 1))
        self.assertTrue(coder.exists())
        self._assert_locked(coder)
        self._assert_locked(build.slot_dir() / "slot-0.lock")

    def test_coder_queue_is_separate_and_reserved_slot_stays_free(self):
        _ticket_fd, integrator = self._hold_ticket(0, "integrator")
        with mock.patch.object(build.subprocess, "call", return_value=0), \
                mock.patch.object(build.time, "sleep", side_effect=AssertionError("coder queued behind integrator")):
            self.assertEqual(build.run(["not-executed"], build_class="coder"), 0)
        record = json.loads((build.slot_dir() / "waits.log").read_text())
        self.assertEqual((record["class"], record["slot"]), ("coder", 1))
        self.assertTrue(integrator.exists())
        self._hold_slot(0)

    def test_fresh_ticket_creation_is_protected_before_its_flock(self):
        create = tempfile.mkstemp
        created = []

        def inspect_fresh_ticket(*args, **kwargs):
            fd, name = create(*args, **kwargs)
            created.append(Path(name))
            try:
                self._assert_locked(self._queue() / "guard.lock")
                # At this point the ticket itself has not yet been flocked.
                probe = os.open(name, os.O_RDWR)
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
                self.assertTrue(Path(name).exists())
                return fd, name
            except BaseException:
                os.close(fd)
                raise

        with mock.patch.object(tempfile, "mkstemp", side_effect=inspect_fresh_ticket):
            self._acquire(1, timeout=0)
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())
        self._assert_guard_free()

    def test_queue_guard_is_not_held_during_polling(self):
        occupied = self._hold_slot(0)

        def free_slot(_seconds):
            self._assert_guard_free()
            self._release(occupied)

        with mock.patch.object(build.time, "sleep", side_effect=free_slot):
            self._acquire(1)


if __name__ == "__main__":
    unittest.main()
