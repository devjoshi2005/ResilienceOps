import json,os
import requests
from datetime import datetime
from jira import JIRA
import pandas as pd

# Jira config
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL") # Eg: "https://<projectname>.atlassian.net/"
JIRA_PROJECT_KEY = "SEC"  # your project key
JIRA_ISSUE_TYPE = "10001"   # ID for issue type
JIRA_EMAIL = os.getenv("MAIL_URL") #personal/business mail used for jira account signup/login
JIRA_API_TOKEN = os.getenv("JIRA_TOKEN")  

AUTH = (JIRA_EMAIL, JIRA_API_TOKEN)

jira = JIRA(
    server=JIRA_BASE_URL,
    basic_auth=(JIRA_EMAIL, JIRA_API_TOKEN)
)


def create_jira_ticket(incident):
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"CRITICAL SECURITY INCIDENT: {incident['event_type']} (Risk {incident['risk_score']})",
            "description": (
            f"Risk Score: {incident['risk_score']}\n"
            f"Severity: {incident['severity']}\n"
            f"Type: {incident['event_type']}\n"
            f"Resource: {incident['resource_arn']}\n"
            f"Description: {incident['description']}\n"
            f"Timestamp: {incident['timestamp']}"
            ),
            "issuetype": {"id": JIRA_ISSUE_TYPE},
            "priority": {"name": "Highest"},
            "labels": ["security", "critical", "auto-generated"]
        }
    }

    try:
        new_issue = jira.create_issue(fields=payload["fields"])
        print(f"Issue created: {new_issue.key}")
        return new_issue.key
    except Exception as e:
        print(f"Failed to create issue: {str(e)}")
        return None

DESTINATIONFILE=f"/tmp/anomalies-list/anomalies-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.json"

with open(DESTINATIONFILE, "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)

critical = df[(df['risk_score'] >= 100) | (df['severity'].str.lower() == 'critical')].copy()

services = ['eks', 's3', 'ec2', 'iam']
critical = critical[critical['resource_arn'].str.lower().str.contains('|'.join(services))]

# Dedup IAM: group by unique ARN + event_type, keep highest risk
critical_iam = critical[critical['resource_arn'].str.lower().str.contains('iam')]
critical_iam = critical_iam.groupby(['resource_arn', 'event_type']).agg({'risk_score': 'max'}).reset_index()
critical_iam = critical_iam.merge(critical, on=['resource_arn', 'event_type', 'risk_score'], how='inner')
critical_non_iam = critical[~critical['resource_arn'].str.lower().str.contains('iam')]
critical = pd.concat([critical_iam, critical_non_iam]).drop_duplicates(subset=['resource_arn', 'event_type'])

critical = critical.sort_values('risk_score', ascending=False)

# Convert back to list of dicts
critical_list = critical.to_dict('records')

for inc in critical_list:
    ticket_key = create_jira_ticket(inc)
    if ticket_key:
        print(f"Created: {ticket_key} - {inc['event_type']} (risk {inc['risk_score']})")
