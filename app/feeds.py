"""Lifecycle management for the optional telemetry feed subprocesses.

The SIEM itself only matches rules against events already in the database; it
never generates events on its own. These three scripts are the data sources:

- "machine"   forwarders/host_forwarder.py   this PC's real processes/connections
- "incidents" scripts/replay_dataset.py       real historical attack log, looped
- "synthetic" scripts/simulate_traffic.py     synthetic traffic covering all rules

FeedManager starts/stops each as a subprocess on demand (e.g. from dashboard
buttons) rather than auto-starting them, so the SIEM can run as a pure
machine monitor until the user opts into replay/synthetic data.
"""
import atexit
import os
import subprocess
import sys
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FEEDS = {
    "machine": {
        "label": "Machine Monitor",
        "description": "Watches this PC's real processes and outbound connections.",
        "args": ["forwarders/host_forwarder.py"],
    },
    "incidents": {
        "label": "Real Incident Logs",
        "description": "Replays a real historical SSH attack log on repeat.",
        "args": ["scripts/replay_dataset.py", "--loop"],
    },
    "synthetic": {
        "label": "Synthetic Traffic",
        "description": "Generates synthetic benign + attack events covering all rules.",
        "args": ["scripts/simulate_traffic.py"],
    },
}


class FeedManager:
    def __init__(self):
        self._processes = {}
        self._lock = threading.Lock()
        atexit.register(self.stop_all)

    def start(self, name):
        if name not in FEEDS:
            raise ValueError(f"Unknown feed: {name}")
        with self._lock:
            existing = self._processes.get(name)
            if existing and existing.poll() is None:
                return False  # already running
            env = os.environ.copy()
            env["PYTHONPATH"] = BASE_DIR
            proc = subprocess.Popen(
                [sys.executable, *FEEDS[name]["args"]],
                cwd=BASE_DIR,
                env=env,
            )
            self._processes[name] = proc
            return True

    def stop(self, name):
        if name not in FEEDS:
            raise ValueError(f"Unknown feed: {name}")
        with self._lock:
            proc = self._processes.get(name)
            if not proc or proc.poll() is not None:
                return False  # not running
            proc.terminate()
            return True

    def is_running(self, name):
        with self._lock:
            proc = self._processes.get(name)
            return bool(proc and proc.poll() is None)

    def status(self):
        return {name: self.is_running(name) for name in FEEDS}

    def stop_all(self):
        with self._lock:
            for proc in self._processes.values():
                if proc.poll() is None:
                    proc.terminate()


feed_manager = FeedManager()
