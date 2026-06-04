import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from feature_extraction import extract_features

app = Flask(__name__)

# --- Settings and model loading ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Load models and scaler directly from AI_Model_Builder
MODELS_DIR = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "models")
SCALER_PATH = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "scaler.joblib")
DATASET_PATH = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "dataset", "webshell_features.csv")

# Select the model to use
MODEL_NAME = "XGBoost.joblib"
MODEL_PATH = os.path.join(MODELS_DIR, MODEL_NAME)

# Probability threshold
PROBABILITY_THRESHOLD = 0.50

print("[SERVER] Loading model and scaler")
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    
    # Load feature names to avoid warnings
    df_sample = pd.read_csv(DATASET_PATH, nrows=1)
    feature_names = df_sample.drop('label', axis=1).columns
    print(f"[SERVER] {MODEL_NAME} loaded and ready on port 5000")
except Exception as e:
    print(f"[SERVER] Startup error: {e}")
    exit()


@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Analyze files sent by agents"""

    if 'file' not in request.files:
        return jsonify({"error": "File not found"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # Save the file temporarily
    temp_path = os.path.join(BASE_DIR, f"temp_{secure_filename(file.filename)}")
    file.save(temp_path)
    
    try:
        # Extract features on the server side
        features = extract_features(temp_path, label=0)
        
        # Delete the temp file right after analysis
        if os.path.exists(temp_path):
            os.remove(temp_path)

        if not features:
            return jsonify({"error": "Failed to extract features"}), 500

        # ML prediction
        features_df = pd.DataFrame([features]).drop('label', axis=1)
        features_scaled = pd.DataFrame(scaler.transform(features_df), columns=feature_names)

        if hasattr(model, "predict_proba"):
            malicious_prob = model.predict_proba(features_scaled)[0][1]
            is_malicious = 1 if malicious_prob >= PROBABILITY_THRESHOLD else 0
        else:
            is_malicious = int(model.predict(features_scaled)[0])
            malicious_prob = 1.0 if is_malicious == 1 else 0.0

        # Response back to the agent
        if is_malicious == 1:
            print(f"[ALARM] Malicious file detected: {file.filename} ({malicious_prob*100:.1f}%)")
            return jsonify({
                "status": "MALICIOUS", 
                "probability": float(malicious_prob),
                "message": "Web shell detected"
            })
        else:
            print(f"[INFO] Clean file: {file.filename}")
            return jsonify({
                "status": "BENIGN", 
                "probability": float(malicious_prob),
                "message": "File is clean"
            })

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Start on 0.0.0.0 so other machines can connect
    app.run(host='0.0.0.0', port=5000, debug=False)