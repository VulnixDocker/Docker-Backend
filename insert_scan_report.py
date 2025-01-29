import mysql.connector
import os

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.getenv("MYSQL_USER", "flask_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "docker_management")

try:
    db = mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL!")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scanner_name VARCHAR(50),
            report_text TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

except Exception as e:
    print(f"❌ MySQL Connection Error: {e}")
    exit(1)

def insert_report(scanner_name, file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report_text = file.read()

        sql = """INSERT INTO scan_reports (scanner_name, report_text, scanned_at)
                 VALUES (%s, %s, NOW())"""
        values = (scanner_name, report_text)

        cursor.execute(sql, values)
        db.commit()
        print(f"✅ {scanner_name} report stored successfully")

    except Exception as e:
        print(f"❌ Error storing {scanner_name} report: {e}")

insert_report("Trivy", "trivy-report.txt")
insert_report("Grype", "grype-report.txt")

cursor.close()
db.close()
