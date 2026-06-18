import logging
import os
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime

from forwarders import post_event, load_state, save_state

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

POLL_INTERVAL = float(os.environ.get("SIEM_POLL_INTERVAL", "2"))
STATE_FILE = os.environ.get(
    "SIEM_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".windows_forwarder_state.json"),
)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

HOST_LABEL = os.environ.get("SIEM_HOST_LABEL", socket.gethostname())

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _basename(path):
    if path is None:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def map_sysmon_event(xml_string):
    root = ET.fromstring(xml_string)
    system = root.find(f"{EVENT_NS}System")
    event_id = int(system.find(f"{EVENT_NS}EventID").text)
    system_time = system.find(f"{EVENT_NS}TimeCreated").get("SystemTime")
    timestamp = datetime.fromisoformat(system_time.replace("Z", "+00:00")).isoformat()

    event_data = {}
    for data in root.find(f"{EVENT_NS}EventData"):
        event_data[data.get("Name")] = data.text

    if event_id == 1:
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "process_creation",
            "process_name": _basename(event_data.get("Image")),
            "command_line": event_data.get("CommandLine"),
            "user": event_data.get("User"),
            "details": {"parent_process": _basename(event_data.get("ParentImage"))},
            "raw": xml_string,
        }

    if event_id == 3:
        details = {}
        dest_port = event_data.get("DestinationPort")
        if dest_port is not None:
            try:
                details["dest_port"] = int(dest_port)
            except ValueError:
                pass
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "network_connection",
            "process_name": _basename(event_data.get("Image")),
            "user": event_data.get("User"),
            "dest_ip": event_data.get("DestinationIp"),
            "details": details,
            "raw": xml_string,
        }

    return None



def _record_id(xml_string):
    root = ET.fromstring(xml_string)
    return int(root.find(f"{EVENT_NS}System/{EVENT_NS}EventRecordID").text)


def _get_latest_record_id():
    import win32evtlog

    handle = win32evtlog.EvtQuery(
        SYSMON_CHANNEL,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
    )
    batch = win32evtlog.EvtNext(handle, 1)
    if not batch:
        return 0
    xml_string = win32evtlog.EvtRender(batch[0], win32evtlog.EvtRenderEventXml)
    return _record_id(xml_string)


def _get_new_events(last_record_id):
    import win32evtlog

    query = f"*[System[EventRecordID > {last_record_id}]]"
    handle = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, query)

    events = []
    while True:
        batch = win32evtlog.EvtNext(handle, 10)
        if not batch:
            break
        for raw_event in batch:
            xml_string = win32evtlog.EvtRender(raw_event, win32evtlog.EvtRenderEventXml)
            events.append((_record_id(xml_string), xml_string))
    return events


def main():
    state = load_state(STATE_FILE)
    if "last_record_id" not in state:
        state["last_record_id"] = _get_latest_record_id()
        save_state(state, STATE_FILE)

    while True:
        for record_id, xml_string in _get_new_events(state["last_record_id"]):
            try:
                event = map_sysmon_event(xml_string)
            except Exception as exc:
                logger.warning("Failed to parse Sysmon event (record %s): %s — skipping", record_id, exc)
                state["last_record_id"] = record_id
                save_state(state, STATE_FILE)
                continue
            if event is not None:
                if not post_event(event):
                    break
                logger.info("sent %s from %s", event["event_type"], event["host"])
            state["last_record_id"] = record_id
            save_state(state, STATE_FILE)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
