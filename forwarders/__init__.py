import json
import logging
import os
import tempfile

import requests

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:5000")
SIEM_API_KEY = os.environ.get("SIEM_API_KEY") or os.environ.get("INGEST_API_KEY", "")

_logger = logging.getLogger(__name__)


def post_event(event):
    try:
        headers = {"X-Api-Key": SIEM_API_KEY} if SIEM_API_KEY else {}
        response = requests.post(f"{SIEM_URL}/ingest", json=event, headers=headers, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        _logger.warning("failed to post event: %s", exc)
        return False


def load_state(state_file):
    if not os.path.exists(state_file):
        return {}
    try:
        with open(state_file) as f:
            return json.load(f)
    except json.JSONDecodeError:
        _logger.warning("state file %s is corrupt — resetting", state_file)
        return {}


def save_state(state, state_file):
    dir_ = os.path.dirname(state_file) or "."
    with tempfile.NamedTemporaryFile("w", dir=dir_, delete=False, suffix=".tmp") as tmp:
        json.dump(state, tmp)
        # O1: flush + fsync before rename so the data is durable on disk.
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, state_file)
