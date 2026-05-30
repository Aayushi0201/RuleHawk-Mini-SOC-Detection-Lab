import streamlit as st
import pandas as pd

from engine.rule_loader import load_rules
from engine.detection_engine import run_detection
from engine.report_generator import generate_all_summaries, generate_html_report

from engine.parser import (
    parse_normalized_csv,
    parse_linux_auth_log,
    parse_apache_log,
    parse_sysmon_csv
)

st.set_page_config(
    page_title="RuleHawk - Mini SOC Detection Lab",
    layout="wide"
)

st.title("RuleHawk: Mini SOC Detection Engineering Lab")
st.write("Upload normalized security logs and detect suspicious activity using Sigma-style YAML rules.")


#uploaded_file = st.file_uploader("Upload normalized CSV log file", type=["csv"])
log_type = st.selectbox(
    "Select log type",
    [
        "Normalized CSV",
        "Linux auth.log",
        "Apache access.log",
        "Windows Sysmon CSV"
    ]
)

uploaded_file = st.file_uploader(
    "Upload log file",
    type=["csv", "log", "txt"]
)


rules = load_rules("rules")

st.sidebar.header("Rule Library")
st.sidebar.write(f"Loaded Rules: {len(rules)}")

for rule in rules:
    st.sidebar.write(f"- {rule.get('id')} | {rule.get('title')}")

if uploaded_file is not None:
    
    #logs_df = pd.read_csv(uploaded_file)
    try:
        if log_type == "Normalized CSV":
            logs_df = parse_normalized_csv(uploaded_file)

        elif log_type == "Linux auth.log":
            logs_df = parse_linux_auth_log(uploaded_file)

        elif log_type == "Apache access.log":
            logs_df = parse_apache_log(uploaded_file)

        elif log_type == "Windows Sysmon CSV":
            logs_df = parse_sysmon_csv(uploaded_file)

        else:
            st.error("Unsupported log type selected.")
            st.stop()

    except Exception as e:
        st.error("Log parsing failed.")
        st.write("Please check whether you selected the correct log type for the uploaded file.")
        st.write(f"Selected log type: {log_type}")
        st.write(f"Error details: {e}")
        st.stop()

    st.subheader("Uploaded Logs")
    st.dataframe(logs_df, use_container_width=True)

    alerts = run_detection(logs_df, rules)
    alerts_df = pd.DataFrame(alerts)

    if not alerts_df.empty:
        alerts_df = generate_all_summaries(alerts_df)

    st.subheader("Detection Summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", len(logs_df))
    col2.metric("Alerts Generated", len(alerts_df))
    col3.metric("Rules Loaded", len(rules))

    if not alerts_df.empty:
        st.subheader("SOC Summary")

        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        high_count = len(alerts_df[alerts_df["severity"].str.lower() == "high"])
        medium_count = len(alerts_df[alerts_df["severity"].str.lower() == "medium"])
        critical_count = len(alerts_df[alerts_df["severity"].str.lower() == "critical"])

        unique_ips = alerts_df["src_ip"].nunique()
        avg_risk = round(alerts_df["risk_score"].mean(), 2)
        max_risk = alerts_df["risk_score"].max()

        col1.metric("High Severity", high_count)
        col2.metric("Medium Severity", medium_count)
        col3.metric("Critical Severity", critical_count)
        col4.metric("Suspicious IPs", unique_ips)
        col5.metric("Average Risk", avg_risk)
        col6.metric("Max Risk", max_risk)

        st.write("Alerts by Severity")
        severity_counts = alerts_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        st.bar_chart(severity_counts.set_index("Severity"))

        st.write("Alerts by Log Source")
        source_counts = alerts_df["source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]
        st.bar_chart(source_counts.set_index("Source"))

        st.write("Top Suspicious Source IPs")
        ip_counts = alerts_df["src_ip"].value_counts().reset_index()
        ip_counts.columns = ["Source IP", "Alert Count"]
        st.dataframe(ip_counts, use_container_width=True)

        st.write("MITRE ATT&CK Technique Summary")
        mitre_counts = alerts_df["mitre_tags"].value_counts().reset_index()
        mitre_counts.columns = ["MITRE Tag", "Alert Count"]
        st.dataframe(mitre_counts, use_container_width=True)

        st.write("Alerts by Rule Category")
        category_counts = alerts_df["rule_category"].value_counts().reset_index()
        category_counts.columns = ["Rule Category", "Alert Count"]
        st.dataframe(category_counts, use_container_width=True)

    st.subheader("Alerts")

    if not alerts_df.empty:
        st.dataframe(alerts_df, use_container_width=True)
        st.subheader("Incident Summaries")

        for _, alert in alerts_df.iterrows():
            with st.expander(f"{alert['rule_id']} | {alert['rule_title']} | {alert['severity'].upper()}"):
                st.write(alert["incident_summary"])

        csv = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Alerts CSV",
            data=csv,
            file_name="alerts.csv",
            mime="text/csv"
        )
        
        html_report = generate_html_report(logs_df, alerts_df, rules)

        st.download_button(
            label="Download HTML Incident Report",
            data=html_report,
            file_name="rulehawk_incident_report.html",
            mime="text/html"
        )
        
    else:
        st.success("No alerts detected.")
else:
    st.info("Upload a normalized CSV file to begin analysis.")



st.subheader("Rule Library")

rule_rows = []

for rule in rules:
    logsource = rule.get("logsource", {})
    aggregation = rule.get("aggregation", {})

    rule_rows.append({
        "Rule ID": rule.get("id", ""),
        "Title": rule.get("title", ""),
        "Product": logsource.get("product", ""),
        "Category": logsource.get("category", ""),
        "Severity": rule.get("level", ""),
        "MITRE Tags": ", ".join(rule.get("tags", [])),
        "Rule Type": "Aggregation" if aggregation else "Single Event",
        "Description": rule.get("description", ""),
        "Category": rule.get("category", "uncategorized")
    })

rules_df = pd.DataFrame(rule_rows)
st.dataframe(rules_df, use_container_width=True)



st.subheader("Rule Lab")

if rules:
    selected_rule_title = st.selectbox(
        "Select a rule to inspect",
        [f"{rule.get('id')} | {rule.get('title')}" for rule in rules]
    )

    selected_rule = None

    for rule in rules:
        rule_label = f"{rule.get('id')} | {rule.get('title')}"
        if rule_label == selected_rule_title:
            selected_rule = rule
            break

    if selected_rule:
        col1, col2 = st.columns(2)

        with col1:
            st.write("Rule Metadata")
            st.json({
                "id": selected_rule.get("id", ""),
                "title": selected_rule.get("title", ""),
                "description": selected_rule.get("description", ""),
                "severity": selected_rule.get("level", ""),
                "tags": selected_rule.get("tags", []),
                "logsource": selected_rule.get("logsource", {})
            })

        with col2:
            st.write("Detection Logic")
            st.json(selected_rule.get("detection", {}))

            if selected_rule.get("aggregation"):
                st.write("Aggregation Logic")
                st.json(selected_rule.get("aggregation", {}))

        if uploaded_file is not None and not alerts_df.empty:
            selected_rule_id = selected_rule.get("id", "")
            matched_alerts = alerts_df[alerts_df["rule_id"] == selected_rule_id]

            st.write("Matched Alerts for Selected Rule")
            if not matched_alerts.empty:
                st.dataframe(matched_alerts, use_container_width=True)
            else:
                st.info("No alerts matched this rule for the uploaded log file.")



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