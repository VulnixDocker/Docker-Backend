import mysql.connector
import os
import glob

# Database Config
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.getenv("MYSQL_USER", "flask_user")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "docker_management")

# ✅ Connect to MySQL
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
    exit(1)  # Exit the script if the database connection fails

# ✅ Function to Store Reports in MySQL
def insert_report(scanner_name, file_pattern):
    files = glob.glob(file_pattern)

    if not files:
        print(f"⚠️ WARNING: No reports found for {scanner_name}. Skipping...")
        return

    try:
        # Start a transaction
        db.start_transaction()

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
                print(f"✅ {scanner_name} report stored successfully from {file_path}")

            except Exception as e:
                print(f"❌ Error storing {scanner_name} report from {file_path}: {e}")
                # Rollback the transaction if any INSERT fails
                db.rollback()
                raise  # Re-raise the exception to stop further processing

        # Commit the transaction if all INSERTs succeed
        db.commit()

    except Exception as e:
        print(f"❌ Transaction failed: {e}")
        db.rollback()  # Ensure rollback on any unexpected error
        raise  # Re-raise the exception to stop further processing

# ✅ Ensure at least one report exists before proceeding
if not glob.glob("trivy-*.txt") and not glob.glob("grype-*.txt"):
    print("❌ ERROR: No scan reports found! Exiting without inserting data.")
    exit(1)

# ✅ Store Reports
try:
    insert_report("Trivy", "trivy-*.txt")
    insert_report("Grype", "grype-*.txt")
except Exception as e:
    print(f"❌ Critical error during report insertion: {e}")
    exit(1)  # Exit the script if any report insertion fails

# ✅ Print Final Table Contents
print("🔹 Final Contents of `scan_reports` Table:")
cursor.execute("SELECT id, scanner_name, file_name, scanned_at FROM scan_reports;")
rows = cursor.fetchall()
for row in rows:
    print(row)

# ✅ Close Database Connection
cursor.close()
db.close()