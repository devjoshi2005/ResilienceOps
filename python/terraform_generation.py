import json
import os
from datetime import datetime
from openai import OpenAI
import pandas as pd

# Setup
LLM_MODEL = "gpt-4o"
llm = OpenAI(api_key=os.getenv("OPENAI API KEY"))

DESTINATIONFILE=f"/tmp/anomalies-list/anomalies-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.json"
OUTPUT_TF_FILE = f"/tmp/results/remediation-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.tf"

def generate_remediation(incident):
    prompt = f"""

    You are a Senior code terraform security engineer with many years of experience
    Generate ONLY valid Terraform code (v1.5+) to remediate this incident.
    Include comments explaining each resource.
    Do NOT add provider block or variables.
    Output format: First, a description as multi-line string, then the code.
    Incident details:
    {json.dumps(incident, indent=2)}
    """
    response = llm.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model=LLM_MODEL,
        temperature=0
    )
    output = response.choices[0].message.content.strip()
    desc, code = output.split('\n\n', 1) if '\n\n' in output else (output, "")
    return desc.strip(), code.strip()

with open(DESTINATIONFILE, 'r') as f:
    data = json.load(f)

df = pd.DataFrame(data)

critical = df[(df['risk_score'] >= 100) | (df['severity'].str.lower() == 'critical')].copy()

services = ['eks', 's3', 'ec2', 'iam']
critical = critical[critical['resource_arn'].str.lower().str.contains('|'.join(services))]

critical_iam = critical[critical['resource_arn'].str.lower().str.contains('iam')]
critical_iam = critical_iam.groupby(['resource_arn', 'event_type']).agg({'risk_score': 'max'}).reset_index()
critical_iam = critical_iam.merge(critical, on=['resource_arn', 'event_type', 'risk_score'], how='inner')
critical_non_iam = critical[~critical['resource_arn'].str.lower().str.contains('iam')]
critical = pd.concat([critical_iam, critical_non_iam]).drop_duplicates(subset=['resource_arn', 'event_type'])

critical = critical.sort_values('risk_score', ascending=False)

# Generate and collect
results = []
for _, inc in critical.iterrows():
    desc, code = generate_remediation(inc.to_dict())
    results.append(f"# Description for Incident ID {str(inc['id'])}:\n'''\n{desc}\n'''\n\n{code}\n\n")

# Write to single file
os.makedirs(os.path.dirname(OUTPUT_TF_FILE), exist_ok=True)
with open(OUTPUT_TF_FILE, 'w') as f:
    f.write("\n".join(results))

print(f"Generated remediation for {len(critical)} incidents in {OUTPUT_TF_FILE}")