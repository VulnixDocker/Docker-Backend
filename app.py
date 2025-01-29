from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from functools import wraps
import requests
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)


# Database Configuration (Using Environment Variables for Security)
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER", "flask_user")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB", "docker_management")

mysql = MySQL(app)

# Directories for Uploaded Docker Images & Scan Results
UPLOAD_FOLDER = "uploaded_images"
SCAN_RESULTS_FOLDER = "scan_results"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# GitHub Actions Trigger URL (Replace YOUR_GITHUB_USERNAME & REPO)
GITHUB_ACTIONS_TRIGGER_URL = "https://api.github.com/repos/VulnixDocker/Docker-Backend/actions/workflows/docker-scanner.yml/dispatches"
GITHUB_TOKEN = os.getenv("DOCKER_SCANNER_PAT")  # Stored as a GitHub Secret

# Middleware to ensure admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash("Unauthorized access!", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize Admin User (If Not Exists)
def initialize_admin():
    username = "admin"
    email = "admin@dockerapp.local"
    password = "DISS@!@"
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    admin_exists = cur.fetchone()
    if not admin_exists:
        cur.execute("INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_password, True))
        mysql.connection.commit()
    cur.close()

# 🔹 Home Route
@app.route('/')
def home():
    return render_template('index.html')

# 🔹 Login Page
@app.route('/login-page')
def login_page():
    return render_template('login.html')

# 🔹 Docker Scan Page
@app.route('/dockerscan')
def dockerscan():
    return render_template('dockerscan.html')

# 🔹 User Login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('log')
    password = request.form.get('pwd')

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, password_hash, is_admin FROM users WHERE username = %s", [username])
    result = cur.fetchone()
    cur.close()

    if result and bcrypt.check_password_hash(result[1], password):
        session['user_id'] = result[0]
        session['is_admin'] = result[2]
        flash("Login successful!", "success")
        return redirect(url_for('dockerscan'))
    else:
        flash("Invalid username or password!", "error")
        return redirect(url_for('login_page'))

# 🔹 Upload Docker Image
@app.route('/upload', methods=['POST'])
def upload_image():
    if 'docker_image' not in request.files:
        return jsonify({"error": "No file uploaded!"}), 400

    file = request.files['docker_image']
    if file.filename == '':
        return jsonify({"error": "Invalid file!"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    return jsonify({"message": "Image uploaded successfully!", "image_name": file.filename}), 200

# 🔹 Trigger CI/CD Scan Automatically
@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access!"}), 403

    data = request.json
    image_name = data.get("image_name")

    if not image_name:
        return jsonify({"error": "No image provided!"}), 400

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}"
    }
    payload = {
        "ref": "main",
        "inputs": { "docker_image": image_name }
    }

    # 🛠 Print Debug Info
    print("🔹 Sending Request to GitHub Actions")
    print(f"🔹 Headers: {headers}")
    print(f"🔹 Payload: {payload}")

    response = requests.post(GITHUB_ACTIONS_TRIGGER_URL, headers=headers, json=payload)

    print(f"🔹 Response Code: {response.status_code}")
    print(f"🔹 Response Content: {response.text}")

    if response.status_code == 204:
        return jsonify({"message": "Scan triggered successfully!"}), 200
    else:
        return jsonify({"error": "Failed to trigger scan!", "details": response.json()}), 500


# 🔹 Dashboard to View Scan Reports
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, scanner_name, report_text, scanned_at FROM scan_reports WHERE user_id = %s ORDER BY scanned_at DESC", (user_id,))
    reports = cur.fetchall()
    cur.close()

    return render_template("dashboard.html", reports=reports)

# 🔹 Download Scan Report
@app.route('/download/<int:report_id>')
def download_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    cur.execute("SELECT scanner_name, report_text FROM scan_reports WHERE id = %s AND user_id = %s", (report_id, user_id))
    report = cur.fetchone()
    cur.close()

    if report:
        filename = f"{report[0]}_scan_report.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report[1])

        return send_file(filename, as_attachment=True)

    return "Report not found or unauthorized", 403

# 🔹 Admin Dashboard
@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# 🔹 Run Flask App
if __name__ == '__main__':
    with app.app_context():
        initialize_admin()
    app.run(debug=True)
