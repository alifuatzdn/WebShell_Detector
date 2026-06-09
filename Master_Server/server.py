import os
import joblib
import pandas as pd
import socket
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from feature_extraction import extract_features
from dotenv import load_dotenv
import datetime
import json
import warnings

# Suppress standard sklearn warnings when feeding raw DataFrames to pipelines.
warnings.filterwarnings("ignore", category=UserWarning)

# Initialize the Flask backend application.
app = Flask(__name__)

# Define dynamic paths to ensure compatibility across different deployment environments.
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Define file paths for persistent dashboard statistics and logs.
DATA_FILE = BASE_DIR / "dashboard_data.json"
MASTER_LOG_FILE = BASE_DIR / "master_scans.log"
AGENT_BANNED_IPS_FILE = PROJECT_ROOT / "Agent_Node" / "banned_ips.txt"


def load_dashboard_data():
    """Loads operational dashboard metrics from the local JSON file safely."""
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)

                # Ensure all required keys exist to prevent frontend rendering errors.
                data.setdefault("total_scans", 0)
                data.setdefault("total_malicious", 0)
                data.setdefault("total_benign", 0)
                data.setdefault("banned_ips", [])
                return data
        except Exception:
            pass

    # Return a default empty state if the file is missing or corrupted.
    return {
        "total_scans": 0,
        "total_malicious": 0,
        "total_benign": 0
    }


def save_dashboard_data(data):
    """Persists operational dashboard metrics to the local JSON file."""
    # Temporarily remove the banned_ips list before saving to avoid duplication.
    if "banned_ips" in data:
        del data["banned_ips"]
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)


# Load global dashboard statistics into memory upon server startup.
dashboard_stats = load_dashboard_data()


def get_banned_ips():
    """Reads the active list of banned IPs directly from the Security Agent's log."""
    if AGENT_BANNED_IPS_FILE.exists():
        with open(AGENT_BANNED_IPS_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []


def get_scan_history():
    """Retrieves the last 100 scan events in reverse chronological order for the dashboard."""
    history = []
    if MASTER_LOG_FILE.exists():
        with open(MASTER_LOG_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        history.append(json.loads(line.strip()))
                    except Exception:
                        pass
    return list(reversed(history[-100:]))


def log_scan_to_file(scan_record):
    """Appends a new scan event securely to the master log file."""
    with open(MASTER_LOG_FILE, 'a') as f:
        f.write(json.dumps(scan_record) + "\n")


# Load environment variables for core server configuration.
load_dotenv(PROJECT_ROOT / ".env")

SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
PROBABILITY_THRESHOLD = float(os.getenv("PROBABILITY_THRESHOLD", "0.50"))

# Target the pipeline models directly, removing the need for a separate scaler file.
MODELS_DIR = PROJECT_ROOT / "AI_Model_Builder" / "models"
MODEL_NAME = os.getenv("MODEL_NAME", "RandomForest_pipeline.joblib")
MODEL_PATH = MODELS_DIR / MODEL_NAME


def get_local_ip():
    """Automatically detects the host machine's local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


print("[SERVER] Loading AI pipeline model...")

# Initialize the machine learning pipeline before accepting any network requests.
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Pipeline model not found: {MODEL_PATH}")

    # Load the unified pipeline containing both the scaler and the classifier.
    pipeline = joblib.load(MODEL_PATH)

except Exception as e:
    print(f"[FATAL] Startup error: {e}")
    print("[FATAL] Ensure AI_Model_Builder has successfully trained the pipeline models.")
    exit(1)


@app.route('/', methods=['GET'])
def welcome():
    """Provides a basic health-check endpoint for the master analysis server."""
    return jsonify({
        "service": "WebShell Detector - Master Analysis Server",
        "status": "running",
        "model": MODEL_NAME,
        "threshold": PROBABILITY_THRESHOLD,
        "dashboard_url": "/dashboard"
    }), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Renders the HTML administrative dashboard displaying live metrics and history."""
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
    """Allows internal agents to report malicious IPs for global banning."""
    req_data = request.json or {}
    ip = req_data.get('ip')

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    # Append the IP to the blocklist if it is not already banned.
    if ip not in get_banned_ips():
        with open(AGENT_BANNED_IPS_FILE, 'a') as f:
            f.write(f"{ip}\n")

    return jsonify({"status": "success", "banned_ips": get_banned_ips()})


@app.route('/analyze', methods=['POST'])
def analyze():
    """Receives files from agents, executes the AI pipeline, and returns the verdict."""
    file = request.files.get('file')

    # Retrieve the true origin IP passed by the Security Agent to log accurately.
    source_ip = request.form.get('original_ip') or request.remote_addr

    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400

    # Save the file temporarily to disk to allow the feature extractor to parse it.
    temp_path = BASE_DIR / f"temp_{secure_filename(file.filename)}"
    file.save(temp_path)

    try:
        # Extract cybersecurity features from the temporary file.
        features = extract_features(str(temp_path), label=0)
        temp_path.unlink(missing_ok=True)

        if not features:
            return jsonify({"error": "Extraction failed"}), 500

        # Construct a DataFrame directly suitable for the Pipeline, ignoring manual scaling.
        features_df = pd.DataFrame([features]).drop('label', axis=1, errors='ignore')

        # Execute the unified pipeline to classify the file based on the threshold.
        if hasattr(pipeline, "predict_proba"):
            prob = float(pipeline.predict_proba(features_df)[0][1])
            is_malicious = prob >= PROBABILITY_THRESHOLD
        else:
            is_malicious = int(pipeline.predict(features_df)[0]) == 1
            prob = 1.0 if is_malicious else 0.0

        # Update global operational metrics.
        dashboard_stats["total_scans"] += 1
        scan_record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": file.filename,
            "probability": round(prob, 4),
            "source_ip": source_ip
        }

        # Process and log the malicious classification outcome.
        if is_malicious:
            dashboard_stats["total_malicious"] += 1
            scan_record["status"] = "MALICIOUS"

            print(f"[ALARM] Malicious file detected: {file.filename} ({prob * 100:.1f}%)")
            save_dashboard_data(dashboard_stats)
            log_scan_to_file(scan_record)

            return jsonify({"status": "MALICIOUS", "probability": prob})

        # Process and log the benign (clean) classification outcome.
        else:
            dashboard_stats["total_benign"] += 1
            scan_record["status"] = "BENIGN"

            print(f"[INFO] Clean file: {file.filename}")
            save_dashboard_data(dashboard_stats)
            log_scan_to_file(scan_record)

            return jsonify({"status": "BENIGN", "probability": prob})

    except Exception as e:
        # Ensure temporary files are securely deleted even if an exception occurs.
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

    # Start the master analytical server.
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)