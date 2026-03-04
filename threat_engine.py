import pandas as pd
import json
from datetime import datetime

# Load threat intelligence feed
threat_feed = pd.read_csv("threat_feed.csv")

malicious_ips = threat_feed[threat_feed["type"] == "ip"]["indicator"].tolist()
malicious_domains = threat_feed[threat_feed["type"] == "domain"]["indicator"].tolist()
malicious_hashes = threat_feed[threat_feed["type"] == "hash"]["indicator"].tolist()

alerts = []
total_risk_score = 0

# --- Network Log Analysis ---
network_logs = pd.read_csv("logs/network_logs.csv")

for _, row in network_logs.iterrows():
    if row["destination_ip"] in malicious_ips:
        risk = threat_feed.loc[
            threat_feed["indicator"] == row["destination_ip"], "risk_score"
        ].values[0]
        
        alerts.append({
            "timestamp": row["timestamp"],
            "type": "Network IOC Match",
            "indicator": row["destination_ip"],
            "risk_score": risk
        })
        total_risk_score += risk

# --- Authentication Log Analysis ---
auth_logs = pd.read_csv("logs/auth_logs.csv")

for _, row in auth_logs.iterrows():
    if row["ip_address"] in malicious_ips:
        risk = threat_feed.loc[
            threat_feed["indicator"] == row["ip_address"], "risk_score"
        ].values[0]

        alerts.append({
            "timestamp": row["timestamp"],
            "type": "Auth IOC Match",
            "indicator": row["ip_address"],
            "risk_score": risk
        })
        total_risk_score += risk

# --- Cloud Log Analysis ---
with open("logs/cloud_logs.json") as f:
    cloud_logs = json.load(f)

for entry in cloud_logs:
    if entry["source_ip"] in malicious_ips:
        risk = threat_feed.loc[
            threat_feed["indicator"] == entry["source_ip"], "risk_score"
        ].values[0]

        alerts.append({
            "timestamp": entry["timestamp"],
            "type": "Cloud IOC Match",
            "indicator": entry["source_ip"],
            "risk_score": risk
        })
        total_risk_score += risk

# --- Generate Report ---
alert_df = pd.DataFrame(alerts)
alert_df.to_csv("reports/threat_alerts.csv", index=False)

# Risk classification
if total_risk_score >= 200:
    overall_risk = "CRITICAL"
elif total_risk_score >= 100:
    overall_risk = "HIGH"
elif total_risk_score > 0:
    overall_risk = "MEDIUM"
else:
    overall_risk = "LOW"

# Executive Summary
with open("reports/executive_summary.txt", "w") as f:
    f.write("Threat Intelligence Correlation Report\n")
    f.write("-------------------------------------\n")
    f.write(f"Total Matches: {len(alerts)}\n")
    f.write(f"Total Risk Score: {total_risk_score}\n")
    f.write(f"Overall Risk Level: {overall_risk}\n")
    f.write(f"Generated On: {datetime.now()}\n")

print("Threat correlation completed.")
print(f"Overall Risk Level: {overall_risk}")