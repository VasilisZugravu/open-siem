"""Replay a REAL captured log dataset into the SIEM through /ingest.

Unlike scripts/seed_demo_data.py and scripts/simulate_traffic.py (which invent synthetic
events), this script parses genuine historical log data using the exact same parser functions
the live forwarders use (forwarders/linux_forwarder.py::parse_auth_log_line,
forwarders/windows_forwarder.py::map_sysmon_event), then POSTs the resulting events to /ingest.

Default dataset (--source auth, no --file/--url given): the OpenSSH_2k.log dataset from the
loghub project (https://github.com/logpai/loghub/tree/master/OpenSSH) - a real, anonymized
production sshd log from a university lab server ("LabSZ"), widely used in log-parsing research.
It contains genuine brute-force activity, including one IP (183.62.140.253) with 286 real
"Failed password" attempts. Used here for non-commercial security-research/demo purposes.

--source sysmon has no bundled dataset (no verified public Sysmon-EventXML dataset was wired
in) - supply your own real Sysmon export via --file, one rendered <Event>...</Event> XML
document per line.

Timestamps in the source dataset are years old, so by default this script rebases them
(--rebase-time, on by default) to a recent window: the Nth parsed event gets a timestamp of
`now + N * --timestamp-step seconds`, preserving original order. This is what lets the SIEM's
aggregation/sequence rules (which only look at recent events) actually fire on replay.
"""
import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

from forwarders.linux_forwarder import parse_auth_log_line
from forwarders.windows_forwarder import map_sysmon_event

DEFAULT_AUTH_LOG_URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
# Same env var the live forwarders read (forwarders/*.py) — lets this script
# authenticate against a SIEM that requires INGEST_API_KEY, same as them.
API_KEY = os.environ.get("SIEM_API_KEY", "")

PARSERS = {
    "auth": parse_auth_log_line,
    "sysmon": map_sysmon_event,
}


def fetch_dataset(url, cache_dir=DATA_DIR):
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, os.path.basename(url))
    if os.path.exists(cache_path):
        return cache_path
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    with open(cache_path, "wb") as f:
        f.write(response.content)
    return cache_path


def load_lines(path, limit=None):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [line.rstrip("\n") for line in f]
    if limit:
        lines = lines[:limit]
    return lines


def parse_events(lines, source):
    parser = PARSERS[source]
    events = []
    for line in lines:
        try:
            event = parser(line)
        except Exception as exc:
            print(f"[warn] Skipping malformed line: {exc}")
            continue
        if event is not None:
            events.append(event)
    return events


def rebase_timestamps(events, step_seconds):
    now = datetime.now(timezone.utc)
    for i, event in enumerate(events):
        event["timestamp"] = (now + timedelta(seconds=i * step_seconds)).isoformat()
    return events


def post_event(base_url, event):
    headers = {"X-Api-Key": API_KEY} if API_KEY else {}
    response = requests.post(f"{base_url}/ingest", json=event, headers=headers)
    response.raise_for_status()
    return response.json()["id"]


def send_events(events, url_base, send_interval, retry_wait=2.0):
    """POST events in order, retrying on connection errors instead of giving up
    (the SIEM may still be starting up when this is launched alongside it).
    A 401 means the API key is missing/wrong, not a transient outage —
    retrying it forever would just spin; fail fast instead."""
    for event in events:
        while True:
            try:
                event_id = post_event(url_base, event)
                print(f"replayed {event['event_type']} on {event['host']} -> id={event_id}")
                break
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 401:
                    print(f"Unauthorized (401) from {url_base}: check SIEM_API_KEY.")
                    sys.exit(1)
                print(f"Could not reach {url_base} ({e}); retrying in {retry_wait}s...")
                time.sleep(retry_wait)
            except requests.exceptions.RequestException as e:
                print(f"Could not reach {url_base} ({e}); retrying in {retry_wait}s...")
                time.sleep(retry_wait)
        if send_interval:
            time.sleep(send_interval)


def main():
    parser = argparse.ArgumentParser(description="Replay a real captured log dataset into the SIEM.")
    parser.add_argument("--source", choices=["auth", "sysmon"], default="auth")
    parser.add_argument("--file", help="local dataset file (overrides --url)")
    parser.add_argument("--url", help="dataset URL to fetch and cache under data/ (auth source defaults to a real loghub OpenSSH dataset)")
    parser.add_argument("--limit", type=int, default=None, help="cap number of raw lines read from the dataset")
    parser.add_argument("--no-rebase", action="store_true", help="keep original (old) timestamps instead of rebasing to now")
    parser.add_argument("--timestamp-step", type=float, default=2.0, help="seconds between consecutive rebased event timestamps (default 2.0)")
    parser.add_argument("--send-interval", type=float, default=0.3, help="seconds to sleep between actual POST requests (default 0.3)")
    parser.add_argument("--url-base", default="http://localhost:5000", help="SIEM base URL (default http://localhost:5000)")
    parser.add_argument("--loop", action="store_true", help="replay the dataset on repeat forever instead of exiting once it's exhausted")
    args = parser.parse_args()

    if args.file:
        dataset_path = args.file
    else:
        url = args.url or (DEFAULT_AUTH_LOG_URL if args.source == "auth" else None)
        if not url:
            print("Error: --source sysmon has no default dataset; pass --file or --url.")
            sys.exit(1)
        print(f"Fetching dataset from {url} ...")
        dataset_path = fetch_dataset(url)

    lines = load_lines(dataset_path, limit=args.limit)
    events = parse_events(lines, args.source)
    print(f"Parsed {len(events)} usable events out of {len(lines)} raw lines.")

    try:
        if args.loop:
            while True:
                pass_events = list(events)
                if not args.no_rebase:
                    pass_events = rebase_timestamps(pass_events, args.timestamp_step)
                send_events(pass_events, args.url_base, args.send_interval)
                print("Dataset exhausted, looping...")
        else:
            pass_events = events
            if not args.no_rebase:
                pass_events = rebase_timestamps(pass_events, args.timestamp_step)
            send_events(pass_events, args.url_base, args.send_interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
