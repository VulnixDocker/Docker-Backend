import mysql.connector
import os
import glob

# ✅ Database Config
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

    # ✅ Create Table If It Doesn't Exist (Storing Report as LONGBLOB)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scanner_name VARCHAR(50),
            report_file LONGBLOB,  # Storing file as binary
            file_name VARCHAR(255),
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
            with open(file_path, "rb") as file:  # Read as binary (for BLOB storage)
                report_data = file.read()

            sql = """INSERT INTO scan_reports (scanner_name, report_file, file_name, scanned_at)
                     VALUES (%s, %s, %s, NOW())"""
            values = (scanner_name, report_data, os.path.basename(file_path))

            cursor.execute(sql, values)
            db.commit()
            print(f"✅ {scanner_name} report stored successfully from {file_path}")

        except Exception as e:
            print(f"❌ Error storing {scanner_name} report from {file_path}: {e}")

# ✅ Ensure at least one report exists before proceeding
if not glob.glob("trivy-*.txt") and not glob.glob("grype-*.txt"):
    print("❌ ERROR: No scan reports found! Exiting without inserting data.")
    exit(1)

# ✅ Store Reports as BLOBs
insert_report("Trivy", "trivy-*.txt")
insert_report("Grype", "grype-*.txt")

# ✅ Close Database Connection
cursor.close()
db.close()
