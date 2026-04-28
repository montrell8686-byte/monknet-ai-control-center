from datetime import datetime, timedelta
import json
import platform
import subprocess
import time

import psutil
from flask import Flask, jsonify, render_template


app = Flask(__name__)

SECURITY_CACHE_SECONDS = 10
RAPID_ATTEMPT_WINDOW_SECONDS = 60
RAPID_ATTEMPT_MIN_COUNT = 3
security_cache = {"updated": 0, "data": None}
security_state = {"seen_keys": set(), "total_failed_attempts": 0}


@app.route("/")
def dashboard():
    return render_template("index.html")


def simulated_failed_logins():
    now = datetime.now()
    return [
        {
            "timestamp": (now - timedelta(seconds=12)).strftime("%Y-%m-%d %I:%M:%S %p"),
            "ip": "203.0.113.42",
            "account": "administrator",
            "type": "Failed login",
        },
        {
            "timestamp": (now - timedelta(seconds=31)).strftime("%Y-%m-%d %I:%M:%S %p"),
            "ip": "203.0.113.42",
            "account": "administrator",
            "type": "Failed login",
        },
        {
            "timestamp": (now - timedelta(seconds=48)).strftime("%Y-%m-%d %I:%M:%S %p"),
            "ip": "203.0.113.42",
            "account": "administrator",
            "type": "Failed login",
        },
        {
            "timestamp": (now - timedelta(minutes=4)).strftime("%Y-%m-%d %I:%M:%S %p"),
            "ip": "198.51.100.17",
            "account": "monknet-admin",
            "type": "Failed login",
        },
        {
            "timestamp": (now - timedelta(minutes=9)).strftime("%Y-%m-%d %I:%M:%S %p"),
            "ip": "N/A",
            "account": "guest",
            "type": "Failed login",
        },
    ]


def read_windows_failed_logins():
    command = r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 -ErrorAction Stop
$events | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $eventData = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $eventData[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
        timestamp = $_.TimeCreated.ToString('yyyy-MM-dd hh:mm:ss tt')
        ip = if ($eventData['IpAddress'] -and $eventData['IpAddress'] -ne '-') { $eventData['IpAddress'] } else { 'N/A' }
        account = if ($eventData['TargetUserName']) { $eventData['TargetUserName'] } else { 'Unknown' }
        type = 'Failed login'
    }
} | ConvertTo-Json -Depth 3
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=6,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return [], "windows-security-log-unavailable"

    events = json.loads(result.stdout)
    if isinstance(events, dict):
        events = [events]

    return events, "Windows Security Event Log"


def parse_event_datetime(timestamp):
    for date_format in ("%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(timestamp, date_format)
        except (TypeError, ValueError):
            continue

    return datetime.now()


def format_duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def event_key(event):
    return "|".join(
        [
            str(event.get("timestamp", "")),
            str(event.get("ip", "")),
            str(event.get("account", "")),
            str(event.get("type", "")),
        ]
    )


def normalize_security_events(events):
    normalized_events = []
    for event in events:
        event_time = parse_event_datetime(event.get("timestamp"))
        normalized_events.append(
            {
                "timestamp": event_time.strftime("%Y-%m-%d %I:%M:%S %p"),
                "timestamp_epoch": event_time.timestamp(),
                "ip": event.get("ip") or "N/A",
                "account": event.get("account") or "Unknown",
                "type": event.get("type") or "Failed login",
                "delta": "First seen",
                "rapid": False,
            }
        )

    normalized_events.sort(key=lambda item: item["timestamp_epoch"], reverse=True)
    for index, event in enumerate(normalized_events):
        if index + 1 >= len(normalized_events):
            continue

        previous_event = normalized_events[index + 1]
        delta_seconds = event["timestamp_epoch"] - previous_event["timestamp_epoch"]
        event["delta"] = f"+{format_duration(delta_seconds)} since previous"
        event["rapid"] = 0 <= delta_seconds <= RAPID_ATTEMPT_WINDOW_SECONDS

    return normalized_events


def has_rapid_repeated_attempts(events):
    for index, event in enumerate(events):
        burst_key = event["ip"] if event["ip"] != "N/A" else event["account"]
        burst_count = 0
        for candidate in events[index:]:
            candidate_key = candidate["ip"] if candidate["ip"] != "N/A" else candidate["account"]
            if candidate_key != burst_key:
                continue

            if event["timestamp_epoch"] - candidate["timestamp_epoch"] <= RAPID_ATTEMPT_WINDOW_SECONDS:
                burst_count += 1

        if burst_count >= RAPID_ATTEMPT_MIN_COUNT:
            return True

    return False


def update_total_failed_attempts(events):
    for event in events:
        key = event_key(event)
        if key in security_state["seen_keys"]:
            continue

        security_state["seen_keys"].add(key)
        security_state["total_failed_attempts"] += 1


def threat_level(attempts, rapid_detected):
    if attempts >= 6 or rapid_detected:
        return "HIGH"
    if attempts >= 3:
        return "MEDIUM"
    return "LOW"


def get_security_events():
    now = time.time()
    if security_cache["data"] and now - security_cache["updated"] < SECURITY_CACHE_SECONDS:
        return security_cache["data"]

    source = "Detection Mode: Simulated Events (Testing Phase)"
    events = simulated_failed_logins()
    if platform.system() == "Windows":
        try:
            windows_events, windows_source = read_windows_failed_logins()
            if windows_events:
                events = windows_events
                source = windows_source
            else:
                source = f"{windows_source}; Detection Mode: Simulated Events (Testing Phase)"
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            source = "Windows Security Event Log blocked; Detection Mode: Simulated Events (Testing Phase)"

    normalized_events = normalize_security_events(events)
    rapid_detected = has_rapid_repeated_attempts(normalized_events)
    update_total_failed_attempts(normalized_events)
    total_attempts = security_state["total_failed_attempts"]
    data = {
        "attempts": total_attempts,
        "recent_attempts": len(normalized_events),
        "rapid_detected": rapid_detected,
        "threat_level": threat_level(total_attempts, rapid_detected),
        "source": source,
        "events": normalized_events[:5],
    }
    security_cache.update({"updated": now, "data": data})
    return data


@app.route("/api/stats")
def stats():
    return jsonify(
        {
            "cpu": psutil.cpu_percent(interval=0.1),
            "ram": psutil.virtual_memory().percent,
            "time": datetime.now().strftime("%I:%M:%S %p"),
            "security": get_security_events(),
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
