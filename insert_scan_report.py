import mysql.connector
import os

# Fetch credentials from environment variables
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.getenv("MYSQL_USER", "flask_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "docker_management")

# Connect to MySQL
try:
    db = mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL!")
except Exception as e:
    print(f"❌ MySQL Connection Error: {e}")
    exit(1)

# Insert scan results
def insert_report(scanner_name, file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report_text = file.read()

        sql = """INSERT INTO scan_reports (user_id, scanner_name, report_text, scanned_at)
                 VALUES (%s, %s, %s, NOW())"""
        values = (1, scanner_name, report_text)

        cursor.execute(sql, values)
        db.commit()
        print(f"✅ {scanner_name} report stored successfully")

    except Exception as e:
        print(f"❌ Error storing {scanner_name} report: {e}")

insert_report("Trivy", "trivy-report.txt")
insert_report("Grype", "grype-report.txt")

cursor.close()
db.close()
