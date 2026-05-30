def generate_incident_summary(alert):
    """
    Generates an analyst-style incident summary for one alert.
    """

    rule_title = alert.get("rule_title", "Unknown Detection")
    severity = alert.get("severity", "unknown")
    src_ip = alert.get("src_ip", "N/A")
    user = alert.get("user", "N/A")
    match_count = alert.get("match_count", 1)
    alert_type = alert.get("alert_type", "single_event")
    mitre_tags = alert.get("mitre_tags", "N/A")
    description = alert.get("description", "")

    if alert_type == "aggregation":
        summary = (
            f"A {severity.upper()} severity alert was generated for '{rule_title}'. "
            f"The detection was triggered because {match_count} related events were observed "
            f"from source IP {src_ip}. "
            f"This behavior may indicate repeated suspicious activity. "
            f"The detection maps to MITRE ATT&CK tag(s): {mitre_tags}. "
            f"Analyst note: {description}"
        )
    else:
        summary = (
            f"A {severity.upper()} severity alert was generated for '{rule_title}'. "
            f"The event involved source IP {src_ip} and user {user}. "
            f"The activity matched a suspicious detection rule. "
            f"The detection maps to MITRE ATT&CK tag(s): {mitre_tags}. "
            f"Analyst note: {description}"
        )

    return summary


def generate_all_summaries(alerts_df):
    """
    Adds an incident_summary column to the alerts dataframe.
    """

    if alerts_df.empty:
        return alerts_df

    alerts_df = alerts_df.copy()
    alerts_df["incident_summary"] = alerts_df.apply(
        lambda row: generate_incident_summary(row.to_dict()),
        axis=1
    )

    return alerts_df


def generate_html_report(logs_df, alerts_df, rules):
    """
    Generates a complete HTML incident report for RuleHawk.
    """

    total_logs = len(logs_df)
    total_alerts = len(alerts_df)
    total_rules = len(rules)

    if alerts_df.empty:
        severity_html = "<p>No alerts generated.</p>"
        source_html = "<p>No alerts generated.</p>"
        ip_html = "<p>No suspicious IPs found.</p>"
        mitre_html = "<p>No MITRE techniques detected.</p>"
        alerts_table_html = "<p>No alerts detected.</p>"
        summaries_html = "<p>No incident summaries available.</p>"
    else:
        severity_counts = alerts_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]

        source_counts = alerts_df["source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]

        ip_counts = alerts_df["src_ip"].value_counts().reset_index()
        ip_counts.columns = ["Source IP", "Alert Count"]

        mitre_counts = alerts_df["mitre_tags"].value_counts().reset_index()
        mitre_counts.columns = ["MITRE Tag", "Alert Count"]

        severity_html = severity_counts.to_html(index=False)
        source_html = source_counts.to_html(index=False)
        ip_html = ip_counts.to_html(index=False)
        mitre_html = mitre_counts.to_html(index=False)

        display_columns = [
            "timestamp",
            "source",
            "event_type",
            "user",
            "src_ip",
            "rule_id",
            "rule_title",
            "severity",
            "mitre_tags",
            "alert_type",
            "match_count"
        ]

        existing_columns = [
            col for col in display_columns if col in alerts_df.columns
        ]

        alerts_table_html = alerts_df[existing_columns].to_html(index=False)

        summaries = []

        for _, alert in alerts_df.iterrows():
            summaries.append(
                f"""
                <div class="summary-box">
                    <h3>{alert.get("rule_id", "")} | {alert.get("rule_title", "")}</h3>
                    <p><strong>Severity:</strong> {alert.get("severity", "")}</p>
                    <p>{alert.get("incident_summary", "")}</p>
                </div>
                """
            )

        summaries_html = "\n".join(summaries)


    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>RuleHawk Incident Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                background-color: #f5f7fa;
                color: #222;
            }}

            h1 {{
                color: white;
            }}

            h2 {{
                color: black;
            }}

            .header {{
                background-color: #111827;
                color: white;
                padding: 20px;
                border-radius: 8px;
            }}

            .metric-container {{
                display: flex;
                gap: 20px;
                margin-top: 20px;
                margin-bottom: 20px;
            }}

            .metric-card {{
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                width: 30%;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}

            table {{
                border-collapse: collapse;
                width: 100%;
                background-color: white;
                margin-bottom: 20px;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
                font-size: 14px;
            }}

            th {{
                background-color: #e5e7eb;
            }}

            .section {{
                background-color: white;
                padding: 20px;
                margin-top: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}

            .summary-box {{
                background-color: #f9fafb;
                border-left: 5px solid #374151;
                padding: 15px;
                margin-bottom: 15px;
            }}

            .footer {{
                margin-top: 30px;
                font-size: 12px;
                color: #666;
            }}
        </style>
    </head>

    <body>
        <div class="header">
            <h1>RuleHawk Incident Report</h1>
            <p>Mini SOC Detection Engineering Lab</p>
        </div>

        <div class="metric-container">
            <div class="metric-card">
                <h2>{total_logs}</h2>
                <p>Total Logs Analyzed</p>
            </div>

            <div class="metric-card">
                <h2>{total_alerts}</h2>
                <p>Total Alerts Generated</p>
            </div>

            <div class="metric-card">
                <h2>{total_rules}</h2>
                <p>Rules Loaded</p>
            </div>
        </div>

        <div class="section">
            <h2>Severity Summary</h2>
            {severity_html}
        </div>

        <div class="section">
            <h2>Alerts by Log Source</h2>
            {source_html}
        </div>

        <div class="section">
            <h2>Top Suspicious Source IPs</h2>
            {ip_html}
        </div>

        <div class="section">
            <h2>MITRE ATT&CK Summary</h2>
            {mitre_html}
        </div>

        <div class="section">
            <h2>Detailed Alert Table</h2>
            {alerts_table_html}
        </div>

        <div class="section">
            <h2>Incident Summaries</h2>
            {summaries_html}
        </div>

        <div class="footer">
            <p>Generated by RuleHawk: Mini SOC Detection Engineering Lab.</p>
        </div>
    </body>
    </html>
    """

    return html