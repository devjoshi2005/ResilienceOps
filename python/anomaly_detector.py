"""
Anomaly detection on security events
Uses Isolation Forest for unsupervised anomaly detection
"""

import sqlite3,os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import json

DB_PATH = f"/tmp/collections/resilienceops-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.db"
DESTINATIONFILE=f"/tmp/anomalies-list/anomalies-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.json"




def load_events(hours=24):
    """Load recent events from database"""
    conn = sqlite3.connect(DB_PATH)
    
    query = """
        SELECT * FROM security_events 
        WHERE timestamp > datetime('now', '-{} hours')
        ORDER BY timestamp DESC
    """.format(hours)
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def engineer_features(df):
    features = pd.DataFrame()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    features['hour'] = df['timestamp'].dt.hour
    features['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Severity normalized 0-1 (IBM Cost of Data Breach: higher severity = higher cost)
    df['severity'] = df['severity'].astype(str).str.lower()
    severity_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
    features['severity_score'] = df['severity'].map(severity_map)
    df['severity_num'] = pd.to_numeric(df['severity'], errors='coerce')

    features['severity_score'] = features['severity_score'].fillna(
        df['severity_num'] / 10.0
    )

    event_freq = df['event_type'].value_counts(normalize=True)
    features['event_rarity'] = df['event_type'].map(lambda x: 1 - event_freq.get(x, 0))
    
    features['resource_count'] = df.groupby('timestamp')['resource_arn'].transform('nunique').fillna(1)
    features['multi_source'] = df.groupby('timestamp')['source'].transform('nunique').fillna(1)
    features['scope'] = (features['resource_count'] + features['multi_source'] * 2) / 3
    
    return features

def detect_anomalies(df, contamination=0.1):
    """Run Isolation Forest anomaly detection"""
    if len(df) < 10:
        print("Not enough data for anomaly detection")
        return df
    
    features = engineer_features(df)
    
    model = IsolationForest(
        contamination=contamination,  
        random_state=42,
        n_estimators=100
    )
    
    features_array = features.fillna(0).values

    model.fit(features_array)
    df['anomaly_score'] = model.decision_function(features_array)
    df['is_anomaly'] = model.predict(features_array)
    df['is_anomaly'] = df['is_anomaly'].apply(lambda x: 1 if x == -1 else 0)
    
    df['risk_score'] = (
        features['severity_score'] * 40 +
        df['is_anomaly'] * 30 +
        features['event_rarity'] * 20 +
        features['scope'] * 10
    ).clip(0, 100)
    
    return df

def get_critical_incidents(min_risk_score=70):
    """Get incidents requiring immediate response"""
    df = load_events(hours=1)  
    
    if len(df) == 0:
        return []
    
    df = detect_anomalies(df)
    
    critical = df[df['risk_score'] >= min_risk_score].copy()
    critical = critical.sort_values('risk_score', ascending=False)
    
    incidents = []
    for _, row in critical.iterrows():
        incident = {
            'id': row['id'],
            'timestamp': str(row['timestamp']),
            'source': row['source'],
            'severity': row['severity'],
            'event_type': row['event_type'],
            'description': row['description'],
            'resource_arn': row['resource_arn'],
            'risk_score': row['risk_score'],
            'anomaly_score': row['anomaly_score'],
            'raw_json': row['raw_json']
        }
        incidents.append(incident)
    try:
        os.makedirs(os.path.dirname(DESTINATIONFILE), exist_ok=True)
        with open(DESTINATIONFILE, 'w') as f:
            json.dump(incidents, f, indent=2)
    except Exception as e:
        print(f"Error writing anomalies to file: {e}")
    return len(incidents)

if __name__ == "__main__":
    print("Running anomaly detection...")
    
    incidents = get_critical_incidents(min_risk_score=60)
    
    if incidents:
        print(f"\n{incidents} CRITICAL INCIDENTS DETECTED:\n")
        print("no errors found means good")
    else:
        print("No critical incidents detected")