import json
import mysql.connector
import time

# Wait for MySQL to be ready
time.sleep(10)

# Connect to MySQL inside GitHub Actions
db = mysql.connector.connect(
    host="127.0.0.1",
    user="flask_user",
    password="Abhiram@1729",
    database="docker_management"
)
cursor = db.cursor()

# Insert scan results
def insert_report(scanner_name, file_path):
    try:
        with open(file_path, "r") as file:
            report_json = json.load(file)

        sql = """INSERT INTO scan_reports (user_id, scanner_name, report_json)
                 VALUES (%s, %s, %s)"""
        values = (1, scanner_name, json.dumps(report_json))

        cursor.execute(sql, values)
        db.commit()
        print(f"✅ {scanner_name} report stored successfully")

    except Exception as e:
        print(f"❌ Error storing {scanner_name} report: {e}")

insert_report("Trivy", "trivy-report.json")
insert_report("Grype", "grype-report.json")

cursor.close()
db.close()
