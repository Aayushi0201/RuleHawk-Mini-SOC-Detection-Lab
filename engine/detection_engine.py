def get_risk_score(severity):
    """
    Converts severity level into numeric risk score.
    """
    severity = str(severity).lower()

    severity_scores = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100
    }

    return severity_scores.get(severity, 0)


def value_contains_any(value, patterns):
    """
    Checks whether a field value contains any pattern from a list.
    Matching is case-insensitive.
    """
    if value is None:
        return False

    value = str(value).lower()

    for pattern in patterns:
        if str(pattern).lower() in value:
            return True

    return False


def match_rule(row, rule):
    """
    Matches a single log row against the selection part of a rule.
    Supports:
    - exact field matching
    - field_contains matching
    """
    selection = rule.get("detection", {}).get("selection", {})

    for field, expected in selection.items():
        if field.endswith("_contains"):
            actual_field = field.replace("_contains", "")
            actual_value = row.get(actual_field, "")

            if not value_contains_any(actual_value, expected):
                return False

        else:
            actual_value = str(row.get(field, "")).strip().lower()
            expected_value = str(expected).strip().lower()

            if actual_value != expected_value:
                return False

    return True


def match_exclusions(row, rule):
    """
    Checks whether a log row matches exclusion conditions.
    If it matches exclusions, the event should be ignored.
    """
    exclusions = rule.get("exclusions", {})

    if not exclusions:
        return False

    for field, expected in exclusions.items():
        if field.endswith("_contains"):
            actual_field = field.replace("_contains", "")
            actual_value = row.get(actual_field, "")

            if value_contains_any(actual_value, expected):
                return True

        else:
            actual_value = str(row.get(field, "")).strip().lower()
            expected_value = str(expected).strip().lower()

            if actual_value == expected_value:
                return True

    return False


def create_basic_alert(row_dict, rule):
    """
    Creates a normal one-event alert.
    """
    return {
        "timestamp": row_dict.get("timestamp", ""),
        "source": row_dict.get("source", ""),
        "event_type": row_dict.get("event_type", ""),
        "user": row_dict.get("user", ""),
        "src_ip": row_dict.get("src_ip", ""),
        "rule_id": rule.get("id", ""),
        "rule_title": rule.get("title", ""),
        "severity": rule.get("level", ""),
        "risk_score": get_risk_score(rule.get("level", "")),
        "rule_category": rule.get("category", "uncategorized"),
        "mitre_tags": ", ".join(rule.get("tags", [])),
        "description": rule.get("description", ""),
        "alert_type": "single_event",
        "match_count": 1
    }


def create_aggregation_alert(group_value, group_df, rule, group_by):
    """
    Creates one alert for grouped/aggregated detections.
    Example: 6 failed SSH logins from same IP.
    """
    first_event = group_df.iloc[0].to_dict()
    last_event = group_df.iloc[-1].to_dict()

    return {
        "timestamp": last_event.get("timestamp", ""),
        "source": last_event.get("source", ""),
        "event_type": last_event.get("event_type", ""),
        "user": last_event.get("user", ""),
        "src_ip": group_value if group_by == "src_ip" else last_event.get("src_ip", ""),
        "rule_id": rule.get("id", ""),
        "rule_title": rule.get("title", ""),
        "severity": rule.get("level", ""),
        "risk_score": get_risk_score(rule.get("level", "")),
        "rule_category": rule.get("category", "uncategorized"),
        "mitre_tags": ", ".join(rule.get("tags", [])),
        "description": rule.get("description", ""),
        "alert_type": "aggregation",
        "match_count": len(group_df),
        "aggregation_field": group_by,
        "aggregation_value": group_value,
        "first_seen": first_event.get("timestamp", ""),
        "last_seen": last_event.get("timestamp", "")
    }


def run_single_event_detection(logs_df, rule):
    """
    Runs normal row-by-row detection.
    """
    alerts = []

    for _, row in logs_df.iterrows():
        row_dict = row.to_dict()

        if match_rule(row_dict, rule) and not match_exclusions(row_dict, rule):
            alerts.append(create_basic_alert(row_dict, rule))

    return alerts


def run_aggregation_detection(logs_df, rule):
    """
    Runs aggregation-based detection.
    Example:
    - Match failed login events
    - Group by src_ip
    - Alert if count > threshold
    """
    matched_rows = []

    for _, row in logs_df.iterrows():
        row_dict = row.to_dict()

        if match_rule(row_dict, rule) and not match_exclusions(row_dict, rule):
            matched_rows.append(row_dict)

    if not matched_rows:
        return []

    import pandas as pd

    matched_df = pd.DataFrame(matched_rows)

    aggregation = rule.get("aggregation", {})
    group_by = aggregation.get("group_by")
    threshold = aggregation.get("threshold", 1)
    condition = aggregation.get("condition", "count_greater_than")

    if not group_by or group_by not in matched_df.columns:
        return []

    alerts = []

    for group_value, group_df in matched_df.groupby(group_by):
        count = len(group_df)

        if condition == "count_greater_than" and count > threshold:
            alerts.append(create_aggregation_alert(group_value, group_df, rule, group_by))

        elif condition == "count_greater_equal" and count >= threshold:
            alerts.append(create_aggregation_alert(group_value, group_df, rule, group_by))

    return alerts


def run_correlation_detection(logs_df, rule):
    """
    Runs correlation-based detection.

    Example:
    - Multiple failed SSH login attempts from same IP
    - Followed by successful SSH login from same IP
    """
    correlation = rule.get("correlation", {})

    group_by = correlation.get("group_by", "src_ip")
    failed_pattern = str(correlation.get("failed_pattern", "")).lower()
    success_pattern = str(correlation.get("success_pattern", "")).lower()
    threshold = correlation.get("threshold", 5)

    if group_by not in logs_df.columns:
        return []

    alerts = []

    logs_df = logs_df.copy()
    logs_df["timestamp"] = logs_df["timestamp"].astype(str)
    logs_df = logs_df.sort_values(by="timestamp")

    for group_value, group_df in logs_df.groupby(group_by):
        failed_events = []
        success_event = None

        for _, row in group_df.iterrows():
            row_dict = row.to_dict()

            if match_exclusions(row_dict, rule):
                continue

            message = str(row_dict.get("message", "")).lower()

            if failed_pattern in message:
                failed_events.append(row_dict)

            if success_pattern in message and len(failed_events) >= threshold:
                success_event = row_dict
                break

        if success_event:
            first_failed = failed_events[0]

            alerts.append({
                "timestamp": success_event.get("timestamp", ""),
                "source": success_event.get("source", ""),
                "event_type": success_event.get("event_type", ""),
                "user": success_event.get("user", ""),
                "src_ip": group_value if group_by == "src_ip" else success_event.get("src_ip", ""),
                "rule_id": rule.get("id", ""),
                "rule_title": rule.get("title", ""),
                "severity": rule.get("level", ""),
                "risk_score": get_risk_score(rule.get("level", "")),
                "rule_category": rule.get("category", "uncategorized"),
                "mitre_tags": ", ".join(rule.get("tags", [])),
                "description": rule.get("description", ""),
                "alert_type": "correlation",
                "match_count": len(failed_events) + 1,
                "aggregation_field": group_by,
                "aggregation_value": group_value,
                "first_seen": first_failed.get("timestamp", ""),
                "last_seen": success_event.get("timestamp", ""),
                "correlation_summary": (
                    f"{len(failed_events)} failed login attempts followed by "
                    f"a successful login from {group_by}={group_value}"
                )
            })

    return alerts


def run_detection(logs_df, rules):
    """
    Main detection runner.

    Supports:
    - single-event detection
    - aggregation detection
    - correlation detection
    """
    all_alerts = []

    for rule in rules:
        if "correlation" in rule:
            alerts = run_correlation_detection(logs_df, rule)

        elif "aggregation" in rule:
            alerts = run_aggregation_detection(logs_df, rule)

        else:
            alerts = run_single_event_detection(logs_df, rule)

        all_alerts.extend(alerts)

    return all_alerts