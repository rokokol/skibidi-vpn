"""The probes' arithmetic, on kernel files written by hand.

The collector runs from a timer, so it cannot watch an interval go by. The
machine's CPU time therefore leaves as the running totals /proc/stat keeps,
and a dashboard takes the rate of each. That makes the arithmetic the whole
contract: the total is every state the kernel names before guest, the busy
part is what is not idle, and a file the machine cannot answer must cost its
rows rather than arrive as a zero.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "roles" / "metrics" / "files"
SCRIPT = LIB / "skibidi-metrics.py"
sys.path.insert(0, str(LIB))


def load():
    spec = importlib.util.spec_from_file_location("skibidi_metrics_probes", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# user nice system idle iowait irq softirq steal, then guest guest_nice. A
# guest's time is already inside user and nice, so the sum must stop before it
STAT = "cpu  100 0 50 800 50 0 0 0 40 20\ncpu0 50 0 25 400 25 0 0 0 20 10\nintr 1\n"


class TestCpuTotals(unittest.TestCase):
    def setUp(self):
        self.module = load()

    def test_busy_is_every_state_but_idle(self):
        # 50 of the 200 busy seconds are iowait: a CPU waiting on a disk is
        # not idle, and the host dashboard this pair feeds counts it as busy
        busy, total = self.module.cpu_totals(STAT)
        self.assertEqual(busy, 200.0)
        self.assertEqual(total, 1000.0)

    def test_guest_and_guest_nice_are_not_counted_twice(self):
        # guest 40 and guest_nice 20 are already inside user 100 and nice 0;
        # adding them would make the total 1060
        _busy, total = self.module.cpu_totals(STAT)
        self.assertEqual(total, 1000.0)

    def test_a_line_with_fewer_than_eight_states_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.cpu_totals("cpu  1 2 3 4 5 6 7\n")

    def test_a_state_that_is_not_a_number_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.cpu_totals("cpu  1 2 3 idle 5 6 7 8\n")

    def test_a_file_without_the_aggregate_line_is_refused(self):
        # cpu0 and the rest are per-CPU lines; the machine's own total is the
        # line spelled "cpu"
        with self.assertRaises(ValueError):
            self.module.cpu_totals("cpu0 1 2 3 4 5 6 7 8\nintr 1\n")


class TestMemoryRatio(unittest.TestCase):
    def setUp(self):
        self.module = load()

    def test_used_is_what_mem_available_does_not_cover(self):
        # Not 1 - MemFree: the kernel's MemAvailable already counts reclaimable
        # page cache as free, and MemFree alone would read a healthy node as full
        text = "MemTotal: 1000 kB\nMemFree: 600 kB\nMemAvailable: 250 kB\n"
        self.assertEqual(self.module.memory_ratio(text), 0.75)

    def test_a_file_without_mem_available_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.memory_ratio("MemTotal: 1000 kB\nMemFree: 600 kB\n")

    def test_a_file_without_a_total_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.memory_ratio("MemAvailable: 250 kB\n")

    def test_a_total_of_zero_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.memory_ratio("MemTotal: 0 kB\nMemAvailable: 0 kB\n")


class TestTheProbesOnThisMachine(unittest.TestCase):
    """What the written files cannot answer: that this kernel's files parse"""

    def setUp(self):
        self.module = load()

    def test_the_cpu_probe_runs_with_every_collection(self):
        self.assertIn("probe_cpu", {probe.__name__ for probe in self.module.PROBES})

    @unittest.skipUnless(Path("/proc/stat").exists(), "no /proc on this machine")
    def test_the_cpu_probe_yields_the_pair_a_dashboard_divides(self):
        rows = {(metric, detail): value for metric, detail, value in self.module.probe_cpu()}
        self.assertEqual(set(rows), {("cpu_busy_seconds", ""), ("cpu_seconds", "")})
        busy = rows[("cpu_busy_seconds", "")]
        total = rows[("cpu_seconds", "")]
        self.assertGreater(total, 0)
        self.assertGreaterEqual(busy, 0)
        self.assertLessEqual(busy, total)

    @unittest.skipUnless(Path("/proc/meminfo").exists(), "no /proc on this machine")
    def test_the_memory_probe_reports_a_share_of_the_whole(self):
        rows = dict(((metric, detail), value) for metric, detail, value in self.module.probe_memory())
        ratio = rows[("mem_used_ratio", "")]
        self.assertGreaterEqual(ratio, 0)
        self.assertLessEqual(ratio, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
