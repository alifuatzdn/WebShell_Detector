import os
import joblib
import pandas as pd
import socket
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from feature_extraction import extract_features
from dotenv import load_dotenv
from collections import deque
import datetime
import json

app = Flask(__name__)

# --- In-Memory Analytics & Dashboard Storage ---
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

DATA_FILE = BASE_DIR / "dashboard_data.json"
MASTER_LOG_FILE = BASE_DIR / "master_scans.log"
AGENT_BANNED_IPS_FILE = PROJECT_ROOT / "Agent_Node" / "banned_ips.txt"

def load_dashboard_data():
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                # Ensure all keys exist
                data.setdefault("total_scans", 0)
                data.setdefault("total_malicious", 0)
                data.setdefault("total_benign", 0)
                data.setdefault("banned_ips", [])
                return data
        except Exception:
            pass
    return {
        "total_scans": 0,
        "total_malicious": 0,
        "total_benign": 0
    }

def save_dashboard_data(data):
    # Remove banned_ips from json, as we will read it directly from file
    if "banned_ips" in data:
        del data["banned_ips"]
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

dashboard_stats = load_dashboard_data()

def get_banned_ips():
    if AGENT_BANNED_IPS_FILE.exists():
        with open(AGENT_BANNED_IPS_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def get_scan_history():
    history = []
    if MASTER_LOG_FILE.exists():
        with open(MASTER_LOG_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        history.append(json.loads(line.strip()))
                    except Exception:
                        pass
    return list(reversed(history[-100:]))  # Return latest 100 scans, newest first

def log_scan_to_file(scan_record):
    with open(MASTER_LOG_FILE, 'a') as f:
        f.write(json.dumps(scan_record) + "\n")

# --- Settings & Model Initialization ---
load_dotenv(PROJECT_ROOT / ".env")

SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
PROBABILITY_THRESHOLD = float(os.getenv("PROBABILITY_THRESHOLD", "0.50"))

MODELS_DIR = PROJECT_ROOT / "AI_Model_Builder" / "models"
SCALER_PATH = PROJECT_ROOT / "AI_Model_Builder" / "scaler.joblib"
DATASET_PATH = PROJECT_ROOT / "AI_Model_Builder" / "dataset" / "webshell_features.csv"

MODEL_NAME = os.getenv("MODEL_NAME", "XGBoost.joblib")
MODEL_PATH = MODELS_DIR / MODEL_NAME


# Helper function to get Network IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


print("[SERVER] Loading model and scaler...")
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    df_sample = pd.read_csv(DATASET_PATH, nrows=1)
    feature_names = df_sample.drop('label', axis=1).columns

except Exception as e:
    print(f"[FATAL] Startup error: {e}")
    print("[FATAL] Make sure the AI_Model_Builder folder exists and models are trained.")
    exit(1)


# --- Routes ---
@app.route('/', methods=['GET'])
def welcome():
    return jsonify({
        "service": "WebShell Detector - Master Analysis Server",
        "status": "running",
        "model": MODEL_NAME,
        "threshold": PROBABILITY_THRESHOLD,
        "dashboard_url": "/dashboard"
    }), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    stats_with_ips = dashboard_stats.copy()
    stats_with_ips["banned_ips"] = get_banned_ips()

    return render_template(
        'dashboard.html',
        history=get_scan_history(),
        stats=stats_with_ips,
        model_name=MODEL_NAME
    )


@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    """Endpoint for agents to report an IP to be banned globally"""
    req_data = request.json or {}
    ip = req_data.get('ip')
    if not ip:
        return jsonify({"error": "IP is required"}), 400

    if ip not in get_banned_ips():
        with open(AGENT_BANNED_IPS_FILE, 'a') as f:
            f.write(f"{ip}\n")

    return jsonify({"status": "success", "banned_ips": get_banned_ips()})

@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400

    temp_path = BASE_DIR / f"temp_{secure_filename(file.filename)}"
    file.save(temp_path)

    try:
        features = extract_features(str(temp_path), label=0)
        temp_path.unlink(missing_ok=True)

        if not features:
            return jsonify({"error": "Extraction failed"}), 500

        features_df = pd.DataFrame([features]).drop('label', axis=1, errors='ignore')
        features_scaled = pd.DataFrame(scaler.transform(features_df), columns=feature_names)

        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(features_scaled)[0][1])
            is_malicious = prob >= PROBABILITY_THRESHOLD
        else:
            is_malicious = int(model.predict(features_scaled)[0]) == 1
            prob = 1.0 if is_malicious else 0.0

        dashboard_stats["total_scans"] += 1
        scan_record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": file.filename,
            "probability": round(prob, 4),
            "source_ip": request.remote_addr
        }

        if is_malicious:
            dashboard_stats["total_malicious"] += 1
            scan_record["status"] = "MALICIOUS"

            print(f"[ALARM] Malicious file detected: {file.filename} ({prob * 100:.1f}%)")
            save_dashboard_data(dashboard_stats)
            log_scan_to_file(scan_record)
            return jsonify({"status": "MALICIOUS", "probability": prob})
        else:
            dashboard_stats["total_benign"] += 1
            scan_record["status"] = "BENIGN"

            print(f"[INFO] Clean file: {file.filename}")
            save_dashboard_data(dashboard_stats)
            log_scan_to_file(scan_record)
            return jsonify({"status": "BENIGN", "probability": prob})

    except Exception as e:
        temp_path.unlink(missing_ok=True)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    local_ip = get_local_ip()

    print("\n" + "=" * 50)
    print(" 🧠 MASTER AI SERVER IS RUNNING")
    print("=" * 50)
    print(f" [+] Localhost : http://127.0.0.1:{SERVER_PORT}")
    print(f" [+] Dashboard : http://127.0.0.1:{SERVER_PORT}/dashboard")
    print(f" [+] Network   : http://{local_ip}:{SERVER_PORT}")
    print(f" [i] Model     : {MODEL_NAME}")
    print(f" [i] Threshold : {PROBABILITY_THRESHOLD}")
    print("=" * 50 + "\n")

    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)