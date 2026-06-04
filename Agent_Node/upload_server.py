import os
import uuid
import logging
import socket
from pathlib import Path
from flask import Flask, request
from markupsafe import escape
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from dotenv import load_dotenv

# Initialize the Flask application
app = Flask(__name__)

# --- Configuration & Path Setup ---
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")

UPLOAD_HOST = os.getenv("UPLOAD_HOST", "0.0.0.0")
UPLOAD_PORT = int(os.getenv("UPLOAD_PORT", "8000"))

STAGING_FOLDER = BASE_DIR / "staging"
BANNED_IPS_FILE = BASE_DIR / "banned_ips.txt"
ACCESS_LOG_FILE = BASE_DIR / "access.log"

os.makedirs(STAGING_FOLDER, exist_ok=True)
if not os.path.exists(BANNED_IPS_FILE):
    with open(BANNED_IPS_FILE, 'w') as f:
        pass

# --- Logger Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('access_logger')
logger.addHandler(logging.FileHandler(ACCESS_LOG_FILE))
logger.propagate = False
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# --- HTML & CSS Templates ---
BANNED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Access Denied</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Poppins', sans-serif; background: #f4f7fe; margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: #ffffff; padding: 40px; border-radius: 16px; box-shadow: 0 15px 30px rgba(0, 0, 0, 0.08); max-width: 500px; width: 90%; text-align: center; }
        h2 { color: #c62828; margin-bottom: 25px; font-size: 26px; font-weight: 600; }
        p { color: #34495e; font-size: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Access Denied</h2>
        <p>Your IP address has been banned due to malicious activity.</p>
    </div>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>File Analysis Service</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Poppins', sans-serif; background: #f4f7fe; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }
        .container { background: #ffffff; padding: 40px; border-radius: 16px; box-shadow: 0 15px 30px rgba(0, 0, 0, 0.08); max-width: 500px; width: 90%; text-align: center; margin-top: 50px; }
        h2 { color: #2c3e50; margin-bottom: 25px; font-size: 26px; font-weight: 600; }
        .alert { padding: 16px; margin-bottom: 25px; border-radius: 12px; text-align: center; font-size: 15px; font-weight: 500; }
        .error { background-color: #ff6b6b; color: #ffffff; border: 1px solid transparent; }
        .success { background-color: #2e7d32; color: #ffffff; border: 1px solid transparent; }
        .upload-area { border: 2px dashed #d0d9e6; padding: 50px 20px; border-radius: 16px; background-color: #fdfdff; cursor: pointer; margin-bottom: 25px; transition: all 0.3s ease; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .upload-area:hover { border-color: #4a90e2; background-color: #f8faff; }
        .upload-area div { color: #4a90e2; font-weight: 600; font-size: 18px; }
        .upload-area .supported { font-size: 13px; color: #7f8c8d; margin-top: 10px; font-weight: 400; }
        input[type="file"] { display: none; }
        .upload-btn { background: linear-gradient(135deg, #4a90e2 0%, #50e3c2 100%); color: white; border: none; padding: 14px 20px; border-radius: 12px; cursor: pointer; font-size: 17px; font-weight: 600; width: 100%; transition: all 0.3s ease; box-shadow: 0 5px 15px rgba(74, 144, 226, 0.3); }
        .upload-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(74, 144, 226, 0.4); }
        .file-name { margin-top: 18px; color: #34495e; font-size: 15px; font-weight: 500; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <h2>File Analysis Service</h2>
        __MESSAGE_BLOCK__
        <form method="POST" enctype="multipart/form-data">
            <label for="fileInput" class="upload-area">
                <div>Click or Drag to Upload</div>
                <div class="supported">Analyzes only .php and .txt files</div>
                <div class="file-name" id="fileName"></div>
            </label>
            <input type="file" name="file" id="fileInput" accept=".php,.txt" required>
            <button type="submit" class="upload-btn">Upload & Analyze</button>
        </form>
    </div>
    <script>
        const fileInput = document.getElementById('fileInput');
        const fileNameDiv = document.getElementById('fileName');
        const uploadAreaText = document.querySelector('.upload-area div');

        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                const name = e.target.files[0].name;
                const ext = name.split('.').pop().toLowerCase();
                if (ext !== 'php' && ext !== 'txt') {
                    alert('Invalid file type. Only .php and .txt are allowed.');
                    e.target.value = '';
                    fileNameDiv.textContent = '';
                    uploadAreaText.textContent = "Click or Drag to Upload";
                } else {
                    fileNameDiv.textContent = 'Selected: ' + name;
                    uploadAreaText.textContent = "File Selected";
                }
            } else {
                uploadAreaText.textContent = "Click or Drag to Upload";
                fileNameDiv.textContent = '';
            }
        });
    </script>
</body>
</html>
"""


# --- Helper Functions ---
def get_local_ip():
    """Automatically detects the machine's local network IP address (e.g., 192.168.x.x)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def is_banned(ip: str) -> bool:
    with open(BANNED_IPS_FILE, "r") as f:
        return ip in {line.strip() for line in f if line.strip()}


def get_unique_filepath(filename: str) -> str:
    filepath = STAGING_FOLDER / filename
    if filepath.exists():
        base, ext = os.path.splitext(filename)
        return str(STAGING_FOLDER / f"{base}_{uuid.uuid4().hex[:8]}{ext}")
    return str(filepath)


def render_page(message: str = "", is_success: bool = False):
    message_block = ""
    if message:
        alert_class = "success" if is_success else "error"
        message_block = f'<div class="alert {alert_class}">{escape(message)}</div>'
    return HTML_TEMPLATE.replace("__MESSAGE_BLOCK__", message_block)


# --- Routing ---
@app.before_request
def check_ban():
    if is_banned(request.remote_addr):
        return BANNED_TEMPLATE, 403


@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get('file')
        if not file or not file.filename:
            return render_page("You must select a file to upload.", is_success=False)

        filename = secure_filename(file.filename)
        if not filename.lower().endswith(('.php', '.txt')):
            return render_page("Invalid file type. Only .php and .txt are allowed.", is_success=False)

        save_path = get_unique_filepath(filename)
        file.save(save_path)

        timestamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
        logger.info(f'{request.remote_addr} - - [{timestamp}] "POST / HTTP/1.1" 200 - "{Path(save_path).name}"')

        msg = f"File '{escape(filename)}' uploaded successfully and is being analyzed. It will be published if it is safe."
        return render_page(msg, is_success=True)

    return render_page()


# --- Main Execution ---
if __name__ == "__main__":
    local_ip = get_local_ip()

    print("\n" + "=" * 50)
    print(" 🚀 UPLOAD SERVER IS RUNNING SECURELY")
    print("=" * 50)
    print(f" [+] Localhost : http://127.0.0.1:{UPLOAD_PORT}")
    print(f" [+] Network   : http://{local_ip}:{UPLOAD_PORT}")
    print(f" [i] Staging   : {STAGING_FOLDER}")
    print("=" * 50 + "\n")

    app.run(host=UPLOAD_HOST, port=UPLOAD_PORT, debug=False)