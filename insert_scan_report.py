import mysql.connector
import time

# Wait for MySQL to be ready
time.sleep(10)

# Connect to MySQL inside GitHub Actions
try:
    db = mysql.connector.connect(
        host="127.0.0.1",
        user="flask_user",
        password="Abhiram@1729",
        database="docker_management"
    )
    cursor = db.cursor()
    print("✅ Successfully connected to MySQL!")
except Exception as e:
    print(f"❌ MySQL Connection Error: {e}")
    exit(1)

# Ensure table exists with LONGTEXT for large reports
create_table_sql = """
CREATE TABLE IF NOT EXISTS scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scanner_name VARCHAR(255) NOT NULL,
    report_text LONGTEXT NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""
cursor.execute(create_table_sql)

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
