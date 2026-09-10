"""Offline F6a collector contract; production activation is deliberately absent."""
import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from model_council import executor as ex


@contextmanager
def child(code):
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [sys.executable, '-B', '-c', 'import os,sys,time\np=' + str(write_fd) + '\n' + code],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, pass_fds=(write_fd,), env={}, start_new_session=True,
    )
    os.close(write_fd)
    try:
        yield process, read_fd
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        try:
            os.close(read_fd)
        except OSError:
            pass


WRITE = '''
def emit(fd, data):
    while data:
        n = os.write(fd, data[:65536])
        data = data[n:]
'''


class CollectorContract(unittest.TestCase):
    def collect(self, process, fd, **kwargs):
        self.assertTrue(callable(getattr(ex, '_collect_openai_worker', None)),
                        'inactive bounded collector is missing')
        return ex._collect_openai_worker(
            process, protocol_fd=fd, input=kwargs.pop('input', b''),
            deadline=kwargs.pop('deadline', time.monotonic() + 10), **kwargs)

    def test_policy_values(self):
        expected = {
            '_MAX_WORKER_PROTOCOL_BYTES': 8_000_000,
            '_MAX_WORKER_STDOUT_BYTES': 65_536,
            '_MAX_WORKER_STDERR_BYTES': 65_536,
            '_MAX_WORKER_DIAGNOSTIC_BYTES': 98_304,
            '_WORKER_IO_QUANTUM_BYTES': 65_536,
            '_WORKER_CLEANUP_TIMEOUT_SECONDS': 5.0,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(ex, name, None), value)

    def test_protocol_boundaries(self):
        for size in (7_999_999, 8_000_000, 8_000_001):
            with self.subTest(size=size), child(WRITE +
                    f"emit(p, b'{{}}' + b' ' * ({size}-2))") as (proc, fd):
                result = self.collect(proc, fd)
                self.assertTrue(result.reaped)
                self.assertTrue(result.cleanup_complete)
                self.assertLessEqual(result.protocol_high_water, 8_000_000)
                self.assertLessEqual(result.read_high_water, 65_536)
                if size <= 8_000_000:
                    self.assertIsNone(result.failure)
                    self.assertEqual(len(result.protocol), size)
                    self.assertEqual(result.protocol_high_water, size)
                    self.assertEqual(json.loads(result.protocol), {})
                else:
                    self.assertEqual(result.failure, 'protocol_limit')
                    self.assertIsNone(result.protocol)

    def test_diagnostic_boundaries_and_discard(self):
        for stream in (1, 2):
            for size in (65_535, 65_536, 65_537):
                with self.subTest(stream=stream, size=size), child(WRITE +
                        f"emit({stream}, b'X' * {size})\nemit(p,b'{{}}')") as (proc, fd):
                    result = self.collect(proc, fd)
                    self.assertEqual(result.failure,
                                     None if size <= 65_536 else ('stdout_limit' if stream == 1 else 'stderr_limit'))
                    self.assertEqual(getattr(result, 'stdout_observed' if stream == 1 else 'stderr_observed'), size)
                    self.assertEqual(result.diagnostic_high_water, 0)
                    self.assertNotIn('XXXX', repr(result))

    def test_aggregate_boundary_below_individual_limits(self):
        for total in (98_303, 98_304, 98_305):
            with self.subTest(total=total), child(WRITE +
                    f"emit(1,b'a'*49152)\nemit(2,b'b'*({total}-49152))\nemit(p,b'{{}}')") as (proc, fd):
                result = self.collect(proc, fd)
                self.assertEqual(result.failure, None if total <= 98_304 else 'diagnostic_limit')
                self.assertEqual(result.diagnostic_observed, total)
                self.assertLessEqual(result.stdout_observed, 65_536)
                self.assertLessEqual(result.stderr_observed, 65_536)

    def test_overflow_cancels_before_deadline(self):
        with child(WRITE + "emit(p,b'x'*8000001)\ntime.sleep(30)") as (proc, fd):
            started = time.monotonic()
            result = self.collect(proc, fd, deadline=started + 20)
            self.assertEqual(result.failure, 'protocol_limit')
            self.assertIsNone(result.protocol)
            self.assertTrue(result.reaped)
            self.assertLess(time.monotonic() - started, 5)

    def test_output_before_stdin_does_not_deadlock(self):
        code = WRITE + "emit(p,b' '*200000)\ndata=sys.stdin.buffer.read()\nemit(p,b'{}')\nassert len(data)==300000"
        with child(code) as (proc, fd):
            result = self.collect(proc, fd, input=b'i'*300000)
            self.assertIsNone(result.failure)
            self.assertEqual(json.loads(result.protocol), {})
            self.assertEqual(result.returncode, 0)

    def test_expired_absolute_deadline_is_not_renewed(self):
        with child('time.sleep(30)') as (proc, fd):
            result = self.collect(proc, fd, deadline=time.monotonic()-1)
            self.assertEqual(result.failure, 'deadline')
            self.assertTrue(result.reaped)
            self.assertIsNone(result.protocol)

    def test_zero_exit_after_excess_is_still_failure(self):
        # Small test ceiling lets the child exit before collection starts.
        with child("os.write(1,b'x'*101)\nos.write(p,b'{}')") as (proc, fd):
            proc.wait(timeout=5)
            with patch.object(ex, '_MAX_WORKER_STDOUT_BYTES', 100, create=True):
                result = self.collect(proc, fd)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.failure, 'stdout_limit')
            self.assertIsNone(result.protocol)

    def test_no_diagnostic_content_in_result_or_retained_frame(self):
        sentinel = b'PRIVATE_DIAGNOSTIC_SENTINEL_8675309'
        for overflow in (False, True):
            code = WRITE + f"emit(2,{sentinel!r}*{2200 if overflow else 1})\nemit(p,b'{{}}')"
            with child(code) as (proc, fd):
                result = self.collect(proc, fd)
            self.assertNotIn(sentinel.decode(), repr(result))
            self.assertEqual(result.diagnostic_high_water, 0)
            self.assertFalse(any(isinstance(v, (bytes, bytearray)) and sentinel in v
                                 for v in vars(result).values()))

    def test_new_collector_is_inactive_and_has_no_communicate(self):
        tree = ast.parse(Path(ex.__file__).read_text())
        collector = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
                          and n.name == '_collect_openai_worker'), None)
        self.assertIsNotNone(collector, 'inactive bounded collector is missing')
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr == 'communicate'
                             for n in ast.walk(collector)))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == '_collect_openai_worker']
        self.assertEqual(calls, [])



    def test_real_held_protocol_writer_is_bounded_uncertainty(self):
        read_fd, write_fd = os.pipe()
        proc = subprocess.Popen([sys.executable, '-B', '-c', 'pass'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0, env={})
        try:
            proc.wait(timeout=5)
            started = time.monotonic()
            result = self.collect(proc, read_fd, deadline=started+1)
            self.assertEqual(result.failure, 'cleanup_uncertain')
            self.assertTrue(result.reaped)
            self.assertFalse(result.pipes_eof)
            self.assertFalse(result.cleanup_complete)
            self.assertLess(time.monotonic()-started, 7)
            with self.assertRaises(OSError):
                os.fstat(read_fd)
        finally:
            os.close(write_fd)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()

    def test_collector_does_not_mutate_existing_lifecycle_evidence(self):
        from test_attempt_lifecycle_dispatch import synthetic_writer
        from test_live_contract import make_request
        with synthetic_writer(make_request()) as writer:
            writer.append('sdk_call_boundary', {'wire_request_digest': 'a'*64})
            writer.append('sdk_return_observed')
            before = os.pread(writer.fd, 16000000, 0)
            with child(WRITE + "emit(2,b'PRIVATE_SENTINEL'*10000)") as (proc, fd):
                result = self.collect(proc, fd)
            after = os.pread(writer.fd, 16000000, 0)
            self.assertEqual(before, after)
            self.assertNotIn(b'PRIVATE_SENTINEL', after)
            self.assertEqual(result.failure, 'stderr_limit')
            self.assertEqual([e['event'] for e in writer.events()], [
                'attempt_prepared', 'dispatch_permitted', 'sdk_call_boundary', 'sdk_return_observed'])


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeStream:
    def __init__(self, fd, simulation):
        self.fd = fd
        self.simulation = simulation
        self.closed = False

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True
        self.simulation.closes.append(self.fd)
        if self.simulation.close_error == self.fd:
            raise OSError('PRIVATE_CLOSE_SENTINEL')


class Simulation:
    """Deterministic OS/process seam, not a substitute collector implementation."""
    def __init__(self, *, output=b'', error=b'', protocol=b'{}', exit_at=None,
                 kill_error=False, wait_error=False, held=False, close_error=None):
        self.clock = Clock()
        self.data = {11: output, 12: error, 13: protocol}
        self.exit_at = exit_at
        self.kill_error = kill_error
        self.wait_error = wait_error
        self.held = held
        self.close_error = close_error
        self.killed = False
        self.returncode = None
        self.stdin = FakeStream(10, self)
        self.stdout = FakeStream(11, self)
        self.stderr = FakeStream(12, self)
        self.keys = {}
        self.reads = []
        self.writes = []
        self.closes = []
        self.kill_times = []
        self.waits = []
        self.select_times = []
        self.selector_closed = False

    def kill(self):
        self.kill_times.append(self.clock())
        if self.kill_error:
            raise OSError('PRIVATE_KILL_SENTINEL')
        self.killed = True

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.wait_error:
            raise OSError('PRIVATE_WAIT_SENTINEL')
        if self.killed or (self.exit_at is not None and self.clock() >= self.exit_at):
            self.returncode = -9 if self.killed else 0
            return self.returncode
        if timeout:
            self.clock.now += timeout
        raise subprocess.TimeoutExpired('offline', timeout)

    def register(self, fd, events, data):
        from types import SimpleNamespace
        self.keys[fd] = SimpleNamespace(fd=fd, data=data)

    def unregister(self, fd):
        return self.keys.pop(fd)

    def select(self, timeout):
        self.select_times.append(timeout)
        self.clock.now += min(0.02, timeout)
        return [(key, 0) for key in list(self.keys.values())]

    def close(self):
        self.selector_closed = True

    def read(self, fd, size):
        self.reads.append((fd, size, self.clock()))
        data = self.data[fd]
        if data is None:
            if self.killed and not self.held:
                return b''
            return b'x' * size
        if not data and (self.held or not self.killed and self.exit_at is None):
            raise BlockingIOError()
        result = data[:size]
        self.data[fd] = data[size:]
        return result

    def write(self, fd, data):
        self.writes.append((fd, len(data), self.clock()))
        return len(data)

    @contextmanager
    def installed(self):
        with patch.object(ex, 'selectors', create=True) as selectors, \
             patch.object(ex.os, 'set_blocking'), \
             patch.object(ex.os, 'read', side_effect=self.read), \
             patch.object(ex.os, 'write', side_effect=self.write), \
             patch.object(ex.os, 'close', side_effect=self.closes.append):
            selectors.DefaultSelector.return_value = self
            selectors.EVENT_READ = 1
            selectors.EVENT_WRITE = 2
            yield


# Keep one common assertion seam without inheriting test methods.
class DeterministicContract(unittest.TestCase):
    collect = CollectorContract.collect

    def run_sim(self, sim, *, deadline=101.0, input=b''):
        with sim.installed():
            result = self.collect(sim, 13, deadline=deadline,
                                  input=input, monotonic=sim.clock)
        self.assertTrue(sim.selector_closed)
        self.assertEqual(set(sim.closes), {10, 11, 12, 13})
        self.assertNotIn('PRIVATE_', repr(result))
        return result

    def test_noisy_streams_do_not_starve_peers_input_or_deadline(self):
        sim = Simulation(output=None, error=None, protocol=None)
        with patch.object(ex, '_WORKER_IO_QUANTUM_BYTES', 16, create=True):
            result = self.run_sim(sim, input=b'i'*100000)
        self.assertEqual(result.failure, 'deadline')
        self.assertTrue(result.reaped)
        first_cycle = sim.reads[:3]
        self.assertEqual({fd for fd, _, _ in first_cycle}, {11, 12, 13})
        self.assertTrue(sim.writes)
        self.assertLessEqual(sim.kill_times[0], 101.02)
        self.assertLessEqual(max(n for _, n, _ in sim.writes), 16)
        self.assertEqual(len(sim.kill_times), 1)

    def test_read_requests_obey_remaining_plus_one(self):
        sim = Simulation(output=b'x'*9, protocol=b'{}', exit_at=100)
        with patch.object(ex, '_MAX_WORKER_STDOUT_BYTES', 8, create=True):
            result = self.run_sim(sim)
        self.assertEqual(result.failure, 'stdout_limit')
        self.assertEqual(sim.reads[0][1], 9)
        self.assertEqual(result.stdout_observed, 9)

    def test_aggregate_remaining_restricts_read(self):
        sim = Simulation(output=b'a'*5, error=b'b'*10, exit_at=100)
        with patch.object(ex, '_MAX_WORKER_DIAGNOSTIC_BYTES', 8, create=True):
            result = self.run_sim(sim)
        self.assertEqual(result.failure, 'diagnostic_limit')
        stderr_read = next(n for fd, n, _ in sim.reads if fd == 12)
        self.assertEqual(stderr_read, 4)
        self.assertEqual(result.diagnostic_observed, 9)

    def test_kill_failure_without_reaping_is_uncertain(self):
        sim = Simulation(kill_error=True)
        result = self.run_sim(sim, deadline=100)
        self.assertFalse(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertEqual(result.abort_reason, 'deadline')
        self.assertAlmostEqual(sim.clock(), 105.0)
        self.assertEqual(len(sim.kill_times), 1)

    def test_kill_failure_can_be_followed_by_independently_confirmed_exit(self):
        sim = Simulation(kill_error=True, exit_at=100.1)
        result = self.run_sim(sim, deadline=100)
        self.assertTrue(result.reaped)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(result.failure, 'deadline')

    def test_wait_error_cannot_attest_reaping(self):
        sim = Simulation(wait_error=True)
        result = self.run_sim(sim, deadline=100)
        self.assertFalse(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertLessEqual(sim.clock(), 105.0)

    def test_close_exception_is_uncertain_even_after_reaping(self):
        sim = Simulation(exit_at=100, close_error=11)
        result = self.run_sim(sim)
        self.assertTrue(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertIsNone(result.protocol)

    def test_missing_eof_and_deadline_share_one_cleanup_allowance(self):
        sim = Simulation(exit_at=100, held=True)
        result = self.run_sim(sim, deadline=102)
        self.assertTrue(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertEqual(result.abort_reason, 'deadline')
        self.assertAlmostEqual(sim.clock(), 105.0)
        self.assertEqual(sim.kill_times, [])

    def test_counter_freezes_after_breach_during_discard_drain(self):
        sim = Simulation(output=b'x'*1000)
        with patch.object(ex, '_MAX_WORKER_STDOUT_BYTES', 8, create=True):
            result = self.run_sim(sim)
        self.assertEqual(result.stdout_observed, 9)
        self.assertEqual(result.diagnostic_observed, 9)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(result.failure, 'stdout_limit')
        self.assertGreater(len([fd for fd, _, _ in sim.reads if fd == 11]), 1)


    def test_expiry_during_owned_result_copy_cannot_accept_protocol(self):
        sim = Simulation(protocol=b'{}', exit_at=100)
        class SlowCopy(bytearray):
            def __bytes__(self):
                sim.clock.now = 102
                return bytes(memoryview(self))
        with patch.object(ex, 'bytearray', SlowCopy, create=True):
            result = self.run_sim(sim, deadline=101)
        self.assertEqual(result.failure, 'deadline')
        self.assertIsNone(result.protocol)

    def test_setup_time_consumes_existing_deadline(self):
        sim = Simulation()
        with sim.installed(), patch.object(ex.os, 'set_blocking',
                                           side_effect=lambda *_: setattr(sim.clock, 'now', sim.clock()+0.5)):
            result = self.collect(sim, 13, deadline=101, monotonic=sim.clock)
        self.assertEqual(result.failure, 'deadline')
        self.assertEqual(sim.writes, [])
        self.assertEqual(sim.kill_times, [102.0])

    def test_selector_error_does_not_retain_exception_or_attest_eof(self):
        sim = Simulation()
        with sim.installed(), patch.object(sim, 'select', side_effect=OSError('PRIVATE_SELECTOR_SENTINEL')):
            result = self.collect(sim, 13, deadline=101, monotonic=sim.clock)
        self.assertTrue(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertEqual(result.abort_reason, 'io_error')
        self.assertNotIn('PRIVATE_', repr(result))

    def test_interruptions_are_explicit_and_do_not_escape_with_buffers(self):
        for exc, expected in ((KeyboardInterrupt('PRIVATE_INTERRUPT'), 'keyboard_interrupt'),
                              (SystemExit('PRIVATE_EXIT'), 'system_exit')):
            with self.subTest(expected=expected):
                sim = Simulation()
                with sim.installed(), patch.object(sim, 'select', side_effect=exc):
                    result = self.collect(sim, 13, deadline=101, monotonic=sim.clock)
                self.assertTrue(result.reaped)
                self.assertEqual(result.interruption, expected)
                self.assertEqual(result.abort_reason, 'interrupted')
                self.assertIsNone(result.protocol)
                self.assertNotIn('PRIVATE_', repr(result))

    def test_owned_streams_are_closed_after_registration_failure(self):
        sim = Simulation()
        with sim.installed(), patch.object(sim, 'register', side_effect=OSError('PRIVATE_REGISTER')):
            result = self.collect(sim, 13, deadline=101, monotonic=sim.clock)
        self.assertEqual(set(sim.closes), {10, 11, 12, 13})
        self.assertTrue(result.reaped)
        self.assertFalse(result.cleanup_complete)

    def test_selector_close_failure_prevents_success(self):
        sim = Simulation(exit_at=100)
        with sim.installed(), patch.object(sim, 'close', side_effect=OSError('PRIVATE_CLOSE')):
            result = self.collect(sim, 13, deadline=101, monotonic=sim.clock)
        self.assertTrue(result.reaped)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertIsNone(result.protocol)


    def test_wait_timeout_after_kill_cannot_attest_reaping(self):
        sim = Simulation()
        with sim.installed(), patch.object(sim, 'wait', side_effect=subprocess.TimeoutExpired('offline', 0)):
            result = self.collect(sim, 13, deadline=100, monotonic=sim.clock)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertFalse(result.reaped)
        self.assertTrue(result.pipes_eof)
        self.assertEqual(len(sim.kill_times), 1)
        self.assertAlmostEqual(sim.clock(), 105.0)

    def test_discard_diagnostics_are_arbitrary_bytes_not_text(self):
        sim = Simulation(output=b'\xff\x00\xfe'*20, protocol=b'{}', exit_at=100)
        result = self.run_sim(sim)
        self.assertIsNone(result.failure)
        self.assertEqual(result.stdout_observed, 60)
        self.assertEqual(result.diagnostic_high_water, 0)
        self.assertEqual(result.protocol, b'{}')

    def test_protocol_read_at_exact_ceiling_uses_single_byte_probe(self):
        sim = Simulation(protocol=b'{}'+b' '*6, exit_at=100)
        with patch.object(ex, '_MAX_WORKER_PROTOCOL_BYTES', 8):
            result = self.run_sim(sim)
        self.assertIsNone(result.failure)
        self.assertEqual(result.protocol_high_water, 8)
        self.assertEqual([n for fd, n, _ in sim.reads if fd == 13], [9, 1])

    def test_slow_descriptor_close_consumes_cleanup_allowance(self):
        sim = Simulation(exit_at=100)
        original = sim.stderr.close
        def slow_close():
            original()
            sim.clock.now += 6
        with sim.installed(), patch.object(sim.stderr, 'close', side_effect=slow_close):
            result = self.collect(sim, 13, deadline=120, monotonic=sim.clock)
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(set(sim.closes), {10, 11, 12, 13})

    def test_eof_before_child_exit_still_requires_wait(self):
        sim = Simulation(exit_at=100.3)
        result = self.run_sim(sim)
        self.assertIsNone(result.failure)
        self.assertGreaterEqual(sim.clock(), 100.3)
        self.assertTrue(result.reaped)

    def test_protocol_overflow_stays_latched_despite_cleanup_deadline(self):
        sim = Simulation(protocol=b'x'*9, held=True, exit_at=100)
        with patch.object(ex, '_MAX_WORKER_PROTOCOL_BYTES', 8):
            result = self.run_sim(sim, deadline=101)
        self.assertEqual(result.abort_reason, 'protocol_limit')
        self.assertEqual(result.failure, 'cleanup_uncertain')
        self.assertIsNone(result.protocol)
        self.assertAlmostEqual(sim.clock(), 105.0)


    def test_timely_communication_survives_later_cleanup_crossing_deadline(self):
        for cleanup_target in ('selector', 'descriptor'):
            with self.subTest(cleanup_target=cleanup_target):
                sim = Simulation(protocol=b'{}', exit_at=100)
                copies = []
                class TimedCopy(bytearray):
                    def __bytes__(self):
                        copies.append(sim.clock())
                        return bytes(memoryview(self))
                original_close = sim.close if cleanup_target == 'selector' else sim.stdout.close
                def slow_cleanup():
                    original_close()
                    sim.clock.now += 2
                target = sim if cleanup_target == 'selector' else sim.stdout
                with patch.object(ex, 'bytearray', TimedCopy, create=True), \
                     patch.object(target, 'close', side_effect=slow_cleanup):
                    result = self.run_sim(sim, deadline=101.0)
                self.assertIsNone(result.failure)
                self.assertEqual(result.protocol, b'{}')
                self.assertEqual(len(copies), 1)
                self.assertAlmostEqual(copies[0], 100.04)
                self.assertAlmostEqual(sim.clock(), 102.04)
                self.assertTrue(result.reaped)
                self.assertTrue(result.pipes_eof)
                self.assertTrue(result.cleanup_complete)

    def test_timely_communication_then_late_cleanup_uncertainty_is_not_deadline(self):
        for exceeds_allowance in (False, True):
            with self.subTest(exceeds_allowance=exceeds_allowance):
                sim = Simulation(protocol=b'{}', exit_at=100)
                def uncertain_cleanup():
                    sim.clock.now += 6 if exceeds_allowance else 2
                    if not exceeds_allowance:
                        raise OSError('PRIVATE_CLEANUP_SENTINEL')
                with patch.object(sim, 'close', side_effect=uncertain_cleanup):
                    result = self.run_sim_without_close_assertion(sim)
                self.assertEqual(result.failure, 'cleanup_uncertain')
                self.assertNotEqual(result.abort_reason, 'deadline')
                self.assertTrue(result.reaped)
                self.assertTrue(result.pipes_eof)
                self.assertFalse(result.cleanup_complete)
                self.assertIsNone(result.protocol)

    def run_sim_without_close_assertion(self, sim):
        with sim.installed():
            return self.collect(sim, 13, deadline=101.0, monotonic=sim.clock)

    def test_prior_failure_survives_successful_cleanup_past_communication_deadline(self):
        for reason in ('deadline', 'stdout_limit'):
            with self.subTest(reason=reason):
                sim = Simulation(output=b'x'*9 if reason == 'stdout_limit' else b'', exit_at=100)
                original_close = sim.close
                def slow_cleanup():
                    original_close()
                    sim.clock.now += 2
                with patch.object(ex, '_MAX_WORKER_STDOUT_BYTES', 8), \
                     patch.object(sim, 'close', side_effect=slow_cleanup):
                    result = self.run_sim(sim, deadline=100.0 if reason == 'deadline' else 101.0)
                self.assertEqual(result.failure, reason)
                self.assertEqual(result.abort_reason, reason)
                self.assertTrue(result.cleanup_complete)
                self.assertIsNone(result.protocol)

if __name__ == '__main__':
    unittest.main()
