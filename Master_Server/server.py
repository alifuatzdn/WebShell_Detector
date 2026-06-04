import os
import joblib
import pandas as pd
import socket
from pathlib import Path
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from feature_extraction import extract_features
from dotenv import load_dotenv

app = Flask(__name__)

# --- Settings & Model Initialization ---
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
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
        "threshold": PROBABILITY_THRESHOLD
    }), 200


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

        if is_malicious:
            print(f"[ALARM] Malicious file detected: {file.filename} ({prob * 100:.1f}%)")
            return jsonify({"status": "MALICIOUS", "probability": prob})
        else:
            print(f"[INFO] Clean file: {file.filename}")
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
    print(f" [+] Network   : http://{local_ip}:{SERVER_PORT}")
    print(f" [i] Model     : {MODEL_NAME}")
    print(f" [i] Threshold : {PROBABILITY_THRESHOLD}")
    print("=" * 50 + "\n")

    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)