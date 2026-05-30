import re
import pandas as pd
from datetime import datetime


COMMON_COLUMNS = [
    "timestamp",
    "source",
    "event_type",
    "user",
    "src_ip",
    "process_name",
    "command_line",
    "url",
    "status",
    "message"
]


def ensure_common_columns(df):
    """
    Ensures every normalized dataframe has the same columns.
    Missing columns are added as empty strings.
    """
    for col in COMMON_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    return df[COMMON_COLUMNS]


def parse_normalized_csv(uploaded_file):
    """
    Reads already-normalized CSV logs.
    """
    df = pd.read_csv(uploaded_file)
    return ensure_common_columns(df)


def parse_linux_auth_log(uploaded_file):
    """
    Parses raw Linux auth.log style entries into RuleHawk common schema.
    Handles SSH login attempts, accepted logins, sudo activity, and malformed lines.
    """
    rows = []

    content = uploaded_file.read().decode("utf-8", errors="ignore")
    lines = content.splitlines()

    current_year = datetime.now().year

    for line in lines:
        if not line.strip():
            continue

        row = {
            "timestamp": "",
            "source": "linux",
            "event_type": "auth",
            "user": "",
            "src_ip": "",
            "process_name": "",
            "command_line": "",
            "url": "",
            "status": "",
            "message": line
        }

        timestamp_match = re.match(
            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            line
        )

        if timestamp_match:
            raw_time = timestamp_match.group(1)
            try:
                parsed_time = datetime.strptime(
                    f"{current_year} {raw_time}",
                    "%Y %b %d %H:%M:%S"
                )
                row["timestamp"] = parsed_time.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                row["timestamp"] = raw_time
        else:
            row["event_type"] = "unparsed_auth_log"

        failed_match = re.search(
            r"Failed password for (?:invalid user\s+)?([\w\-.]+) from ([\d\.]+)",
            line
        )
        if failed_match:
            row["user"] = failed_match.group(1)
            row["src_ip"] = failed_match.group(2)

        accepted_match = re.search(
            r"Accepted password for ([\w\-.]+) from ([\d\.]+)",
            line
        )
        if accepted_match:
            row["user"] = accepted_match.group(1)
            row["src_ip"] = accepted_match.group(2)

        sudo_match = re.search(r"sudo:\s+([\w\-.]+)\s+:", line)
        if sudo_match:
            row["user"] = sudo_match.group(1)

        command_match = re.search(r"COMMAND=(.+)$", line)
        if command_match:
            row["command_line"] = command_match.group(1)

        rows.append(row)

    df = pd.DataFrame(rows)
    return ensure_common_columns(df)



def parse_apache_log(uploaded_file):
    """
    Parses raw Apache access logs into RuleHawk common schema.
    Supports common and combined Apache log formats.
    """
    rows = []

    content = uploaded_file.read().decode("utf-8", errors="ignore")
    lines = content.splitlines()

    apache_pattern = re.compile(
        r'(?P<src_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    )

    for line in lines:
        if not line.strip():
            continue

        row = {
            "timestamp": "",
            "source": "web",
            "event_type": "http",
            "user": "",
            "src_ip": "",
            "process_name": "",
            "command_line": "",
            "url": "",
            "status": "",
            "message": line
        }

        match = apache_pattern.search(line)

        if match:
            row["src_ip"] = match.group("src_ip")
            row["url"] = match.group("url")
            row["status"] = match.group("status")

            raw_time = match.group("timestamp")
            try:
                parsed_time = datetime.strptime(
                    raw_time,
                    "%d/%b/%Y:%H:%M:%S %z"
                )
                row["timestamp"] = parsed_time.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                row["timestamp"] = raw_time
        else:
            row["event_type"] = "unparsed_web_log"

        rows.append(row)

    df = pd.DataFrame(rows)
    return ensure_common_columns(df)



def parse_sysmon_csv(uploaded_file):
    """
    Parses Windows Sysmon-style CSV logs into RuleHawk common schema.
    Handles missing columns and missing SourceIp values.
    """

    raw_df = pd.read_csv(uploaded_file)
    rows = []

    for _, row in raw_df.iterrows():
        image = str(row.get("Image", ""))
        process_name = image.split("\\")[-1] if image else ""

        event_id = str(row.get("EventID", ""))

        source_ip = row.get("SourceIp", "")
        if pd.isna(source_ip):
            source_ip = ""

        command_line = row.get("CommandLine", "")
        if pd.isna(command_line):
            command_line = ""

        normalized_row = {
            "timestamp": row.get("UtcTime", ""),
            "source": "windows",
            "event_type": "process_creation" if event_id == "1" else f"event_{event_id}",
            "user": row.get("User", ""),
            "src_ip": source_ip,
            "process_name": process_name,
            "command_line": command_line,
            "url": "",
            "status": "",
            "message": " | ".join([f"{col}={row.get(col, '')}" for col in raw_df.columns])
        }

        rows.append(normalized_row)

    df = pd.DataFrame(rows)
    return ensure_common_columns(df)