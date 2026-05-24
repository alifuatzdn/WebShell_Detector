import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from feature_extraction import extract_features

app = Flask(__name__)

# --- AYARLAR VE MODEL YÜKLEME ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Modeller ve Scaler artık doğrudan AI_Model_Builder içinden okunacak (Kopyalamaya gerek yok)
MODELS_DIR = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "models")
SCALER_PATH = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "scaler.joblib")
DATASET_PATH = os.path.join(PROJECT_ROOT, "AI_Model_Builder", "dataset", "webshell_features.csv")

# Otonom olarak kullanılacak modeli buradan seçebilirsin
MODEL_NAME = "XGBoost.joblib"
MODEL_PATH = os.path.join(MODELS_DIR, MODEL_NAME)

# Olasılık eşik değeri
PROBABILITY_THRESHOLD = 0.50

print("🧠 [SERVER] Yapay Zeka Modeli ve Ölçekleyici Yükleniyor...")
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model bulunamadı: {MODEL_PATH}")
        
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    
    # Uyarıları önlemek için feature isimlerini alıyoruz
    df_sample = pd.read_csv(DATASET_PATH, nrows=1)
    feature_names = df_sample.drop('label', axis=1).columns
    print(f"✅ [SERVER] {MODEL_NAME} başarıyla yüklendi ve 5000 portunda dinlemeye hazır!")
except Exception as e:
    print(f"❌ [SERVER] Başlatma Hatası: {e}")
    exit()


@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Ajanlardan gelen dosyayı analiz eden API Endpoint'i"""
    
    if 'file' not in request.files:
        return jsonify({"error": "Dosya bulunamadı"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "Dosya seçilmedi"}), 400

    # Dosyayı geçici olarak kaydet
    temp_path = os.path.join(BASE_DIR, f"temp_{secure_filename(file.filename)}")
    file.save(temp_path)
    
    try:
        # Sunucu tarafında (Güvenli bölgede) özellik çıkarımı yap!
        features = extract_features(temp_path, label=0)
        
        # Analiz bitti, geçici dosyayı hemen sil
        if os.path.exists(temp_path):
            os.remove(temp_path)

        if not features:
            return jsonify({"error": "Özellikler çıkarılamadı"}), 500

        # Makine Öğrenmesi Tahmini
        features_df = pd.DataFrame([features]).drop('label', axis=1)
        features_scaled = pd.DataFrame(scaler.transform(features_df), columns=feature_names)

        if hasattr(model, "predict_proba"):
            malicious_prob = model.predict_proba(features_scaled)[0][1]
            is_malicious = 1 if malicious_prob >= PROBABILITY_THRESHOLD else 0
        else:
            is_malicious = int(model.predict(features_scaled)[0])
            malicious_prob = 1.0 if is_malicious == 1 else 0.0

        # Ajan'a dönecek yanıt
        if is_malicious == 1:
            print(f"🚨 [ALARM] Zararlı dosya tespit edildi: {file.filename} (Olasılık: %{malicious_prob*100:.1f})")
            return jsonify({
                "status": "MALICIOUS", 
                "probability": float(malicious_prob),
                "message": "Webshell tespit edildi!"
            })
        else:
            print(f"✅ [BİLGİ] Temiz dosya: {file.filename}")
            return jsonify({
                "status": "BENIGN", 
                "probability": float(malicious_prob),
                "message": "Dosya temiz."
            })

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Sunucuyu 0.0.0.0 ile başlatıyoruz ki diğer bilgisayarlar da bağlanabilsin
    app.run(host='0.0.0.0', port=5000, debug=False)