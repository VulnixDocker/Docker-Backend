import json
import mysql.connector
import os

# Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="flask_user",
    password="Abhiram@1729",
    database="docker_management"
)
cursor = db.cursor()

# Retrieve latest user ID (replace with real authentication logic)
cursor.execute("SELECT id FROM users ORDER BY id DESC LIMIT 1")
user_id = cursor.fetchone()[0]

# Function to store report
def insert_report(scanner_name, file_path):
    try:
        with open(file_path, "r") as file:
            report_json = json.load(file)

        sql = """INSERT INTO scan_reports (user_id, scanner_name, report_json)
                 VALUES (%s, %s, %s)"""
        values = (user_id, scanner_name, json.dumps(report_json))

        cursor.execute(sql, values)
        db.commit()
        print(f"✅ {scanner_name} report stored successfully for User ID {user_id}")

    except Exception as e:
        print(f"❌ Error storing {scanner_name} report: {e}")

# Store reports in MySQL
insert_report("Trivy", "trivy-report.json")
insert_report("Grype", "grype-report.json")

cursor.close()
db.close()
