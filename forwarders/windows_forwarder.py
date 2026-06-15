import os
import socket
import xml.etree.ElementTree as ET
from datetime import datetime

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
        return {
            "timestamp": timestamp,
            "host": HOST_LABEL,
            "event_type": "network_connection",
            "process_name": _basename(event_data.get("Image")),
            "user": event_data.get("User"),
            "dest_ip": event_data.get("DestinationIp"),
            "details": {"dest_port": int(event_data.get("DestinationPort"))},
            "raw": xml_string,
        }

    return None
