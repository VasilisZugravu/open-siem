import threading
import time

from flask import current_app

_lock = threading.Lock()


def is_rate_limited(extension_key, ip, max_requests, window_seconds):
    with _lock:
        store = current_app.extensions.setdefault(extension_key, {})
        entry = store.get(ip)
        if entry is None:
            return False
        count, window_start = entry
        if time.monotonic() - window_start > window_seconds:
            del store[ip]
            return False
        return count >= max_requests


def record_request(extension_key, ip, window_seconds):
    with _lock:
        store = current_app.extensions.setdefault(extension_key, {})
        entry = store.get(ip)
        now = time.monotonic()
        if entry is None or now - entry[1] > window_seconds:
            store[ip] = (1, now)
        else:
            count, window_start = entry
            store[ip] = (count + 1, window_start)


def clear(extension_key, ip):
    with _lock:
        current_app.extensions.get(extension_key, {}).pop(ip, None)
