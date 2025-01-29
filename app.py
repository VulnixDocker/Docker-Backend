# from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
# from flask_mysqldb import MySQL
# from flask_bcrypt import Bcrypt
# from functools import wraps
# import subprocess
# import os

# app = Flask(__name__)
# bcrypt = Bcrypt(app)

# # Secret key for sessions
# app.secret_key = 'your_secret_key'

# # Database Configuration
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'flask_user'
# app.config['MYSQL_PASSWORD'] = 'Abhiram@1729'
# app.config['MYSQL_DB'] = 'docker_management'

# mysql = MySQL(app)

# # Path to Snyk binary
# SNYK_PATH = "C:/Users/abhir/Downloads/snyk-win.exe"
# UPLOAD_FOLDER = "./uploaded_images"
# SCAN_RESULTS_FOLDER = "./scan_results"

# # Ensure necessary folders exist
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# # Middleware to ensure admin access
# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         user_id = session.get('user_id')
#         if not user_id:
#             flash("You need to log in first!", "error")
#             return redirect(url_for('login_page'))

#         cur = mysql.connection.cursor()
#         cur.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
#         result = cur.fetchone()
#         cur.close()

#         if not result or not result[0]:
#             flash("Unauthorized access!", "error")
#             return redirect(url_for('home'))
#         return f(*args, **kwargs)
#     return decorated_function

# # Initialize Admin User
# def initialize_admin():
#     username = "admin"
#     email = "admin@dockerapp.local"
#     password = "DISS@!@"
#     hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#     cur = mysql.connection.cursor()
#     cur.execute("SELECT * FROM users WHERE username = %s", (username,))
#     admin_exists = cur.fetchone()
#     if not admin_exists:
#         cur.execute("INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s)",
#                     (username, email, hashed_password, True))
#         mysql.connection.commit()
#     cur.close()

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/signup', methods=['POST'])
# def signup():
#     username = request.form.get('signup_username')
#     email = request.form.get('signup_email')
#     password = request.form.get('signup_password')
#     confirm_password = request.form.get('signup_confirm_password')

#     if password != confirm_password:
#         flash("Passwords do not match!", "error")
#         return redirect(url_for('home'))

#     password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
#                     (username, email, password_hash))
#         mysql.connection.commit()
#         cur.close()
#         flash("Signup successful! You can now log in.", "success")
#         return redirect(url_for('login_page'))
#     except Exception as e:
#         flash(f"Error: {e}", "error")
#         return redirect(url_for('home'))

# @app.route('/login-page', methods=['GET'])
# def login_page():
#     return render_template('login.html')

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.form.get('log')
#     password = request.form.get('pwd')

#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("SELECT id, password_hash, is_admin FROM users WHERE username = %s", [username])
#         result = cur.fetchone()
#         cur.close()

#         if result and bcrypt.check_password_hash(result[1], password):
#             session['user_id'] = result[0]
#             session['is_admin'] = result[2]
#             flash("Login successful!", "success")
#             return redirect(url_for('dashboard'))  # ✅ Fixed Redirect
#         else:
#             flash("Invalid username or password!", "error")
#             return redirect(url_for('login_page'))
#     except Exception as e:
#         flash(f"Error: {e}", "error")
#         return redirect(url_for('login_page'))


# @app.route('/scanning-page', methods=['GET', 'POST'])
# def scanning_page():
#     if 'user_id' not in session:
#         flash("You need to log in first!", "error")
#         return redirect(url_for('login_page'))

#     user_id = session['user_id']

#     if request.method == 'POST':
#         image_name = request.form.get('docker_image_name')

#         if not image_name:
#             flash("Please enter a Docker image name!", "error")
#             return redirect(url_for('scanning_page'))

#         # Trigger GitHub Actions CI/CD
#         flash(f"Scanning Docker image: {image_name}. The report will be available soon.", "info")

#         # Store scan request (status: pending)
#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO scan_reports (user_id, scanner_name, report_json) VALUES (%s, 'Pending', 'Scan in progress...')", (user_id,))
#         mysql.connection.commit()
#         cur.close()

#         return redirect(url_for('dashboard'))

#     return render_template('dockerscan.html')


# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session:
#         return redirect(url_for('login_page'))

#     user_id = session['user_id']

#     db = mysql.connection.cursor()
#     db.execute("SELECT * FROM scan_reports WHERE user_id = %s ORDER BY scanned_at DESC", (user_id,))
#     reports = db.fetchall()
#     db.close()

#     return render_template("dashboard.html", reports=reports)

# @app.route('/download/<int:report_id>')
# def download_report(report_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login_page'))

#     user_id = session['user_id']

#     db = mysql.connection.cursor()
#     db.execute("SELECT scanner_name, report_json FROM scan_reports WHERE id = %s AND user_id = %s", (report_id, user_id))
#     report = db.fetchone()
#     db.close()

#     if report:
#         filename = f"{report[0]}_scan_report.json"
#         with open(filename, "w") as f:
#             json.dump(json.loads(report[1]), f, indent=4)

#         return send_file(filename, as_attachment=True)

#     return "Report not found or unauthorized", 403



# @app.route('/admin')
# @admin_required
# def admin_dashboard():
#     return render_template('admin_dashboard.html')

# @app.route('/admin/manage-users', methods=['GET', 'POST'])
# @admin_required
# def manage_users():
#     cur = mysql.connection.cursor()

#     if request.method == 'POST':
#         username = request.form.get('username')
#         email = request.form.get('email')
#         password = request.form.get('password')
#         confirm_password = request.form.get('confirm_password')
#         role = request.form.get('role')

#         if not username or not email or not password or not confirm_password:
#             flash("All fields are required!", "error")
#             return redirect(url_for('manage_users'))

#         if password != confirm_password:
#             flash("Passwords do not match!", "error")
#             return redirect(url_for('manage_users'))

#         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#         try:
#             cur.execute("""
#                 INSERT INTO users (username, email, password_hash, is_admin)
#                 VALUES (%s, %s, %s, %s)
#             """, (username, email, hashed_password, int(role)))
#             mysql.connection.commit()
#             flash("User added successfully!", "success")
#         except Exception as e:
#             flash(f"Error: {e}", "error")
#         finally:
#             cur.close()

#     cur = mysql.connection.cursor()
#     cur.execute("SELECT id, username, email, is_admin FROM users")
#     users = cur.fetchall()
#     cur.close()

#     return render_template('manage_users.html', users=users)

# if __name__ == '__main__':
#     with app.app_context():
#         initialize_admin()
#     app.run(debug=True)


from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from functools import wraps
import requests
import os
import json

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret key for sessions
app.secret_key = 'your_secret_key'

# Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'flask_user'
app.config['MYSQL_PASSWORD'] = 'Abhiram@1729'
app.config['MYSQL_DB'] = 'docker_management'

mysql = MySQL(app)

UPLOAD_FOLDER = "uploaded_images"
SCAN_RESULTS_FOLDER = "scan_results"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# GitHub Actions Trigger URL
GITHUB_ACTIONS_TRIGGER_URL = "https://api.github.com/repos/YOUR_GITHUB_USERNAME/YOUR_REPO/actions/workflows/docker-scanner.yml/dispatches"
GITHUB_TOKEN = "YOUR_GITHUB_PERSONAL_ACCESS_TOKEN"

# Middleware to ensure admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash("Unauthorized access!", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize Admin User
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('signup_username')
    email = request.form.get('signup_email')
    password = request.form.get('signup_password')
    confirm_password = request.form.get('signup_confirm_password')

    if password != confirm_password:
        flash("Passwords do not match!", "error")
        return redirect(url_for('home'))

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (username, email, password_hash))
    mysql.connection.commit()
    cur.close()

    flash("Signup successful! You can now log in.", "success")
    return redirect(url_for('login_page'))

@app.route('/login-page')
def login_page():
    return render_template('login.html')

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
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password!", "error")
        return redirect(url_for('login_page'))

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
        "inputs": {
            "docker_image": f"uploaded_images/{image_name}"
        }
    }

    response = requests.post(GITHUB_ACTIONS_TRIGGER_URL, headers=headers, json=payload)

    if response.status_code == 204:
        return jsonify({"message": "Scan triggered successfully!"}), 200
    else:
        return jsonify({"error": "Failed to trigger scan!", "details": response.json()}), 500

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

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/manage-users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('manage_users'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur.execute("INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_password, int(role)))
        mysql.connection.commit()

    cur.execute("SELECT id, username, email, is_admin FROM users")
    users = cur.fetchall()
    cur.close()

    return render_template('manage_users.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        initialize_admin()
    app.run(debug=True)

