import os
from typing import Any, cast
from flask import Flask, request
from markupsafe import escape
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "test_www")
LOG_FILE = os.path.join(BASE_DIR, "access.log")
BANNED_IPS_FILE = os.path.join(BASE_DIR, "banned_ips.txt")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if missing
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Write a simple access log entry in an Apache-like format
def log_request(ip, filename):
    import datetime
    now = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0300")
    log_entry = f'{ip} - - [{now}] "POST /upload HTTP/1.1" 200 {filename}\n'

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


# Load banned IPs from the local ban list file
def load_banned_ips():
    if not os.path.exists(BANNED_IPS_FILE):
        return set()

    with open(BANNED_IPS_FILE, "r") as f:
        return {line.strip() for line in f if line.strip()}

# Simple HTML UI embedded in the code
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Image Upload Service</title>
    <style>
        body { font-family: Arial; margin: 50px; background-color: #f4f4f9; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 500px; margin: auto; }
        h2 { color: #333; }
        .alert { padding: 10px; margin-bottom: 20px; border-radius: 4px; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        input[type="file"] { margin: 20px 0; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Profile Image Upload</h2>
        <p>Select a file to upload. Please upload only safe files.</p>

        __MESSAGE_BLOCK__

        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <br>
            <button type="submit">Upload</button>
        </form>
    </div>
</body>
</html>
"""


# Render the upload page with an optional status message
def render_upload_page(message: str = "", success: bool = False):
    message_block = ""
    if message:
        alert_class = "success" if success else "error"
        message_block = f'\n            <div class="alert {alert_class}">\n                {escape(message)}\n            </div>\n        '

    return HTML_TEMPLATE.replace("__MESSAGE_BLOCK__", message_block)

# Handle upload form requests
@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if 'file' not in request.files:
            return render_upload_page("No file selected.", success=False)

        file = cast(Any, request.files['file'])

        client_ip = request.remote_addr

        if client_ip in load_banned_ips():
            return render_upload_page(f"Your IP is banned: {client_ip}", success=False), 403

        if file.filename == '':
            return render_upload_page("No file selected.", success=False)

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Log the uploader IP address
            log_request(client_ip, filename)

            return render_upload_page(f"'{filename}' uploaded successfully.", success=True)

    return render_upload_page("")

if __name__ == "__main__":
    # Silence Flask's default request logs
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    print("[INFO] Upload demo site is running")
    print("[INFO] Open in browser: http://127.0.0.1:8000")
    app.run(host='0.0.0.0', port=8000, debug=False)
