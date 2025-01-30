import mysql.connector
import os
import glob

# Database Config
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.getenv("MYSQL_USER", "flask_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "docker_management")

# ✅ Connect to MySQL
try:
    db = mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL!")

    # ✅ Ensure Table Exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            scanner_name VARCHAR(255) NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            report_text LONGTEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

except Exception as e:
    print(f"❌ MySQL Connection Error: {e}")
    exit(1)

# ✅ Function to Store Reports in MySQL
def insert_report(scanner_name, file_pattern):
    files = glob.glob(file_pattern)

    if not files:
        print(f"⚠️ WARNING: No reports found for {scanner_name}. Skipping...")
        return

    for file_path in files:
        try:
            print(f"🔹 Verifying {scanner_name} report: {file_path}")
            os.system(f"cat {file_path}")  # 🔍 Print the report before inserting

            with open(file_path, "r", encoding="utf-8") as file:
                report_text = file.read()

            file_name = os.path.basename(file_path)  # Extract file name

            sql = """INSERT INTO scan_reports (user_id, scanner_name, file_name, report_text, scanned_at)
                     VALUES (%s, %s, %s, %s, NOW())"""
            values = (1, scanner_name, file_name, report_text)  # Assuming user_id = 1

            cursor.execute(sql, values)
            db.commit()
            
            # ✅ Print inserted row count
            print(f"✅ {scanner_name} report stored successfully from {file_path}")
            cursor.execute("SELECT COUNT(*) FROM scan_reports;")
            count = cursor.fetchone()[0]
            print(f"🔹 Total rows in `scan_reports`: {count}")

        except Exception as e:
            print(f"❌ Error storing {scanner_name} report from {file_path}: {e}")

# ✅ Ensure at least one report exists before proceeding
if not glob.glob("trivy-*.txt") and not glob.glob("grype-*.txt"):
    print("❌ ERROR: No scan reports found! Exiting without inserting data.")
    exit(1)

# ✅ Store Reports
insert_report("Trivy", "trivy-*.txt")
insert_report("Grype", "grype-*.txt")

# ✅ Print Final Table Contents
print("🔹 Final Contents of `scan_reports` Table:")
cursor.execute("SELECT id, scanner_name, file_name, scanned_at FROM scan_reports;")
rows = cursor.fetchall()
for row in rows:
    print(row)

# ✅ Close Database Connection
cursor.close()
db.close()
