import sqlite3
import pandas as pd
from neo4j import GraphDatabase
import os
from datetime import datetime

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = os.getenv("NEO4J_PASSWORD")

DB_PATH = f"/tmp/collections/resilienceops-{f"{str(int(datetime.now().day))}{str(datetime.now().month)}{str(datetime.now().year)}"}.db"


driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))



def import_data(tx, df):
    for _, row in df.iterrows():
        tx.run("""
            MERGE (p:Principal {id: $account_id})
            MERGE (r:Resource {arn: $resource_arn})
            CREATE (e:Event {id: $id, timestamp: $timestamp, source: $source, severity: $severity, event_type: $event_type, description: $description, anomaly_score: $anomaly_score})
            MERGE (p)-[:PERFORMS]->(e)-[:AFFECTS]->(r)
            """, id=row['id'], timestamp=row['timestamp'], source=row['source'], severity=row['severity'], event_type=row['event_type'], description=row['description'], resource_arn=row['resource_arn'], account_id=row['account_id'], anomaly_score=row['anomaly_score'])

conn = sqlite3.connect(DB_PATH)
df = pd.read_sql("SELECT * FROM security_events WHERE severity = 'critical' OR anomaly_score < -0.1", conn)
conn.close()

with driver.session() as session:
    session.execute_write(import_data, df)

driver.close()
print("Import complete")