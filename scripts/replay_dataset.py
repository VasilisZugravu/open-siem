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
from datetime import datetime, timedelta, timezone

import requests

from forwarders.linux_forwarder import parse_auth_log_line
from forwarders.windows_forwarder import map_sysmon_event

DEFAULT_AUTH_LOG_URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

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
        event = parser(line)
        if event is not None:
            events.append(event)
    return events


def rebase_timestamps(events, step_seconds):
    now = datetime.now(timezone.utc)
    for i, event in enumerate(events):
        event["timestamp"] = (now + timedelta(seconds=i * step_seconds)).isoformat()
    return events


def post_event(base_url, event):
    response = requests.post(f"{base_url}/ingest", json=event)
    response.raise_for_status()
    return response.json()["id"]


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

    if not args.no_rebase:
        events = rebase_timestamps(events, args.timestamp_step)

    try:
        for event in events:
            event_id = post_event(args.url_base, event)
            print(f"replayed {event['event_type']} on {event['host']} -> id={event_id}")
            if args.send_interval:
                import time
                time.sleep(args.send_interval)
    except requests.exceptions.RequestException as e:
        print(f"Error: could not reach {args.url_base} ({e}). Is the app running? Try `python run.py` first.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
