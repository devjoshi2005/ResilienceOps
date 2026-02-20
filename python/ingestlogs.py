

import boto3,os
import json
import sqlite3
from datetime import datetime, timedelta
import gzip

DB_PATH = f"/tmp/collections/resilienceops-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.db"

def init_db():
    """Initialize SQLite database for findings"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,  -- 'guardduty' or 'cloudtrail'
            severity TEXT,  -- 'low', 'medium', 'high', 'critical'
            event_type TEXT,
            description TEXT,
            resource_arn TEXT,
            account_id TEXT,
            region TEXT,
            raw_json TEXT,
            anomaly_score REAL DEFAULT 0.0,
            processed INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

def ingest_guardduty_findings(bucket_name, account_id="869935106430", region="ap-south-1"):
    s3 = boto3.client('s3')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now()
    year = str(now.year)
    month = str(now.month).zfill(2)
    day = str(now.day).zfill(2)
    
    prefix = f"AWSLogs/{account_id}/GuardDuty/{region}/{year}/{month}/{day}/"
    print(f"Using prefix: {prefix}")
    
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
    
    findings_count = 0
  
    
    for page in pages:
        contents = page.get('Contents', [])
        print(f"Page objects: {len(contents)}")
        
        for obj in contents:
            key = obj['Key']
            last_mod = obj['LastModified']
            print(f"Key: {key}, Modified: {last_mod}")
            
            if not key.endswith('.jsonl.gz'):
                print(f"Skip {key}: old/format wrong")
                continue
                
            try:
                obj_data = s3.get_object(Bucket=bucket_name, Key=key)
                raw_content = obj_data['Body'].read()
                content = gzip.decompress(raw_content).decode('utf-8')
                print(f"Content len: {len(content)}")

                findings = []
                for line in content.splitlines():
                    if not line.strip():
                        continue
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError as je:
                        print(f"JSON decode error in line: {je}")
                        continue

                print(f"Findings in file: {len(findings)}")

                for finding in findings:
                    timestamp = finding.get('createdAt', now.isoformat())
                    severity = str(finding.get('severity', 5.0))
                    event_type = finding.get('type', 'Unknown')
                    description = finding.get('description', 'No description')
                    
                    resource_arn = finding.get('arn', 'unknown')
                    account_id_f = finding.get('accountId', 'unknown')
                    region_f = finding.get('region', 'unknown')
                    
                    print(f"Insert: type={event_type}, sev={severity}")
                    
                    cursor.execute('''
                        INSERT OR IGNORE INTO security_events 
                        (timestamp, source, severity, event_type, description, resource_arn, account_id, region, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        timestamp, 'guardduty', severity, event_type, description,
                        resource_arn, account_id_f, region_f, json.dumps(finding)
                    ))
                    
                    findings_count += 1
                    
            except Exception as e:
                print(f"Error on {key}: {e}")
                continue
    
    conn.commit()
    conn.close()
    print(f"Ingested {findings_count} GuardDuty findings")
    return findings_count

def ingest_cloudtrail_events(bucket_name, account_id="869935106430", region="ap-south-1"):
    """Pull CloudTrail events from S3 with dynamic date-based filepath"""
    s3 = boto3.client('s3')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now()
    year = str(now.year)
    month = str(now.month).zfill(2)
    day = str(now.day).zfill(2)
    
    prefix = f"AWSLogs/{account_id}/CloudTrail/{region}/{year}/{month}/{day}/"
    
    response = s3.list_objects_v2(
        Bucket=bucket_name,
        Prefix=prefix
    )
    
    events_count = 0
    cutoff_time = datetime.now() - timedelta(hours=24)
    
    for obj in response.get('Contents', []):
        key = obj['Key']
        
        if obj['LastModified'].replace(tzinfo=None) < cutoff_time:
            continue
            
        if not key.endswith('.json.gz'):
            continue
            
        try:
            obj_data = s3.get_object(Bucket=bucket_name, Key=key)
            content = gzip.decompress(obj_data['Body'].read())
            records = json.loads(content)
            
            for record in records.get('Records', []):
                timestamp = record.get('eventTime', datetime.now().isoformat())
                event_type = record.get('eventName', 'Unknown')
                
                # Map CloudTrail to severity
                critical_events = ['PutBucketAcl', 'AuthorizeSecurityGroupIngress', 'AssumeRole', 'CreateAccessKey']
                high_events = ['PutUserPolicy', 'AttachUserPolicy', 'CreateUser']
                
                if event_type in critical_events:
                    severity = 'critical'
                elif event_type in high_events:
                    severity = 'high'
                else:
                    severity = 'low'
                
                description = f"{record.get('eventSource', 'unknown')}: {event_type}"
                resource_arn = record.get('resources', [{}])[0].get('ARN', 'unknown')
                account_id = record.get('recipientAccountId', 'unknown')
                region = record.get('awsRegion', 'unknown')
                
                cursor.execute('''
                    INSERT OR IGNORE INTO security_events 
                    (timestamp, source, severity, event_type, description, resource_arn, account_id, region, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp, 'cloudtrail', severity, event_type, description,
                    resource_arn, account_id, region, json.dumps(record)
                ))
                
                events_count += 1
                
        except Exception as e:
            print(f"Error processing {key}: {e}")
            continue
    
    conn.commit()
    conn.close()
    print(f"Ingested {events_count} CloudTrail events")
    return events_count

if __name__ == "__main__":
    init_db()
    
    ingest_guardduty_findings("guardduty-reports-bucket", account_id="869935106430", region="ap-south-1")
    ingest_cloudtrail_events("soc-demo-cloudtrail-123", account_id="869935106430", region="ap-south-1")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT source, severity, COUNT(*) FROM security_events GROUP BY source, severity")
    for row in cursor.fetchall():
        print(f"{row[0]} | {row[1]}: {row[2]}")
    conn.close()