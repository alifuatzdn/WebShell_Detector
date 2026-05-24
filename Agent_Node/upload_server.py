import os
from typing import Any, cast
from flask import Flask, request
from markupsafe import escape
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

# Yollar
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "test_www")
LOG_FILE = os.path.join(BASE_DIR, "access.log")
BANNED_IPS_FILE = os.path.join(BASE_DIR, "banned_ips.txt")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Klasör yoksa oluştur
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Basit bir loglama fonksiyonu (Gerçek Apache access.log formatına benzer)
def log_request(ip, filename):
    import datetime
    now = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0300")
    log_entry = f'{ip} - - [{now}] "POST /upload HTTP/1.1" 200 {filename}\n'
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def load_banned_ips():
    if not os.path.exists(BANNED_IPS_FILE):
        return set()

    with open(BANNED_IPS_FILE, "r") as f:
        return {line.strip() for line in f if line.strip()}

# Basit bir HTML arayüzü (Ayrı bir HTML dosyası yerine doğrudan kodun içinde)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Resim Yükleme Servisi</title>
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
        <h2>📷 Profil Resmi Yükle</h2>
        <p>Sisteme yüklemek istediğiniz dosyayı seçin. Sadece masum dosyalar yükleyin! 😉</p>

        __MESSAGE_BLOCK__

        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <br>
            <button type="submit">Yükle</button>
        </form>
    </div>
</body>
</html>
"""


def render_upload_page(message: str = "", success: bool = False):
    message_block = ""
    if message:
        alert_class = "success" if success else "error"
        message_block = f'\n            <div class="alert {alert_class}">\n                {escape(message)}\n            </div>\n        '

    return HTML_TEMPLATE.replace("__MESSAGE_BLOCK__", message_block)

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if 'file' not in request.files:
            return render_upload_page("Dosya seçilmedi!", success=False)

        file = cast(Any, request.files['file'])

        client_ip = request.remote_addr

        if client_ip in load_banned_ips():
            return render_upload_page(f"IP adresiniz banlandı: {client_ip}", success=False), 403

        if file.filename == '':
            return render_upload_page("Dosya seçilmedi!", success=False)

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # İsteği yapan kişinin IP'sini log dosyasına yaz
            log_request(client_ip, filename)
            
            return render_upload_page(f"'{filename}' başarıyla yüklendi!", success=True)

    return render_upload_page("")

if __name__ == "__main__":
    # Sadece Log kirliliğini kapatıyoruz
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    print("🌍 Kurban Web Sitesi (Upload Formu) Aktif!")
    print("👉 Tarayıcıdan girin: http://127.0.0.1:8000")
    app.run(host='0.0.0.0', port=8000, debug=False)
