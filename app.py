from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from functools import wraps
import os
import subprocess
import requests
import glob
import traceback

app = Flask(__name__)
bcrypt = Bcrypt(app)

# 🔹 Secret Key for Sessions
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")

# 🔹 Database Configuration (Secure with Env Variables)
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER", "Docker_User")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD", "Abhiram@1729")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB", "docker_management")

mysql = MySQL(app)

# 🔹 Directories for Docker Images & Scan Results
UPLOAD_FOLDER = "uploaded_images"
SCAN_RESULTS_FOLDER = "scan_results"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# 🔹 GitHub Actions Trigger URL
GITHUB_ACTIONS_TRIGGER_URL = "https://api.github.com/repos/VulnixDocker/Docker-Backend/actions/workflows/docker-scanner.yml/dispatches"
GITHUB_TOKEN = os.getenv("DOCKER_SCANNER_PAT")  # Secure Token Storage
if not GITHUB_TOKEN:
    print("❌ ERROR: GitHub PAT is missing! Set DOCKER_SCANNER_PAT in environment variables.")


# 🔹 Middleware: Require Admin Access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash("Unauthorized access!", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# 🔹 Initialize Admin User (If Not Exists)
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

import platform

@app.route('/upload', methods=['POST'])
def upload_image():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized access!"}), 403

        if 'docker_image' not in request.files:
            return jsonify({"error": "No file uploaded!"}), 400

        file = request.files['docker_image']
        if file.filename == '':
            return jsonify({"error": "Invalid file!"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        print(f"✅ File saved successfully: {file_path}")

        # 🔹 Load Image into Docker
        load_result = subprocess.run(["docker", "load", "-i", file_path], capture_output=True, text=True)

        if load_result.returncode != 0:
            print(f"❌ ERROR: Docker load failed! {load_result.stderr}")
            return jsonify({"error": "Failed to load image into Docker", "details": load_result.stderr}), 500

        print(f"✅ Docker Load Output:\n{load_result.stdout}")

        # 🔹 Extract Latest Image
        latest_image = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "--no-trunc"],
            capture_output=True, text=True
        ).stdout.strip().split("\n")[0]  # Get the first image from the list

        if not latest_image:
            return jsonify({"error": "Failed to identify latest Docker image"}), 500

        print(f"✅ Latest Docker image: {latest_image}")

        return jsonify({"message": "Docker image uploaded successfully!", "image_name": latest_image}), 200

    except FileNotFoundError as e:
        print(f"❌ ERROR: File not found! {e}")
        return jsonify({"error": "File not found!", "details": str(e)}), 500

    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Docker command failed - {e.stderr}")
        return jsonify({"error": "Failed to load image into Docker", "details": e.stderr}), 500

    except Exception as e:
        print(f"❌ ERROR: Unexpected issue occurred - {str(e)}")
        import traceback
        traceback.print_exc()  # Print full error traceback
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500




@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access!"}), 403

    data = request.json
    image_name = data.get("image_name")

    if not image_name:
        return jsonify({"error": "No Docker image specified!"}), 400

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}"
    }

    payload = {
        "ref": "main",
        "inputs": {
            "docker_image": image_name  # Ensure correct input format
        }
    }

    try:
        response = requests.post(GITHUB_ACTIONS_TRIGGER_URL, headers=headers, json=payload)

        if response.status_code == 204:
            print(f"✅ Scan triggered successfully for {image_name}!")
            return jsonify({"message": "Scan started successfully!", "image": image_name}), 200
        else:
            print(f"❌ ERROR: Failed to trigger scan! {response.text}")
            return jsonify({"error": "Failed to trigger scan!", "details": response.text}), 500

    except Exception as e:
        print(f"❌ ERROR: Unexpected issue occurred - {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500




# 🔹 View Scan Reports on Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, scanner_name, file_name, scanned_at FROM scan_reports WHERE user_id = %s ORDER BY scanned_at DESC", (user_id,))
    reports = cur.fetchall()
    cur.close()

    return render_template("dashboard.html", reports=reports)


# 🔹 User Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('signup_username')  # Match HTML name
    email = request.form.get('signup_email')  # Match HTML name
    password = request.form.get('signup_password')  # Match HTML name
    confirm_password = request.form.get('signup_confirm_password')  # Match HTML name

    if password != confirm_password:
        flash("Passwords do not match!", "error")
        return redirect(url_for('login_page'))  # Redirect to login page if passwords mismatch

    # Hash the password before storing it
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_password, False))
        mysql.connection.commit()
        cur.close()
        flash("Signup successful! You can now log in.", "success")
        return redirect(url_for('login_page'))
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('login_page'))


# 🔹 Download Scan Report
@app.route('/download/<int:report_id>')
def download_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    cur.execute("SELECT scanner_name, file_name, report_text FROM scan_reports WHERE id = %s AND user_id = %s", (report_id, user_id))
    report = cur.fetchone()
    cur.close()

    if report:
        filename = f"{report[1]}"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report[2])

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







