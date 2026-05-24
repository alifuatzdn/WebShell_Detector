import os
import joblib
import pandas as pd
from feature_extraction import extract_features, calculate_md5
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import warnings

# Gereksiz UserWarning'leri (özellikle feature names uyarısı) gizlemek için
warnings.filterwarnings("ignore", category=UserWarning)

# Yollar
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

test_dir = os.path.join(BASE_DIR, "dataset", "external_data")
normal_dir = os.path.join(test_dir, "normal")
webshell_dir = os.path.join(test_dir, "webshell")
malicious_dir = os.path.join(BASE_DIR, "dataset", "malicious")
benign_dir = os.path.join(BASE_DIR, "dataset", "benign")

# Modeller artık AI_Model_Builder içindeki kendi models/ klasöründen okunuyor
models_dir = os.path.join(BASE_DIR, "models")
scaler_path = os.path.join(BASE_DIR, "scaler.joblib")
dataset_path = os.path.join(BASE_DIR, "dataset", "webshell_features.csv")

# Olasılık eşik değeri
PROBABILITY_THRESHOLD = 0.50

def get_hashes_from_dir(directory):
    hashes = {}
    if os.path.exists(directory):
        folder_name = os.path.basename(directory)
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                file_hash = calculate_md5(file_path)
                if file_hash:
                    hashes[file_hash] = folder_name
    return hashes

# Eğitim seti hash'lerini bir kere hesapla
print("🔍 Eğitim veri setindeki (malicious & benign) dosyaların hash'leri hesaplanıyor...")
training_hashes = {}
training_hashes.update(get_hashes_from_dir(malicious_dir))
training_hashes.update(get_hashes_from_dir(benign_dir))
print(f"✅ Eğitim veri setinde toplam {len(training_hashes)} benzersiz dosya hash'i bulundu.\n")

# Scaler'ı yükle
try:
    scaler = joblib.load(scaler_path)
except Exception as e:
    print(f"Ölçekleyici (Scaler) yüklenemedi: {e}")
    exit()

# src/models/ klasöründeki tüm modelleri bul
if not os.path.exists(models_dir):
    print(f"⚠️ '{models_dir}' klasörü bulunamadı!")
    exit()

model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib')]

if not model_files:
    print(f"⚠️ '{models_dir}' klasöründe test edilecek model bulunamadı!")
    exit()

print(f"🚀 Toplam {len(model_files)} farklı model sırayla test edilecek...\n")

# Orijinal sütun isimlerini yükle (Uyarıları engellemek için DataFrame'i yeniden isimlendireceğiz)
try:
    df_sample = pd.read_csv(dataset_path, nrows=1)
    feature_names = df_sample.drop('label', axis=1).columns
except FileNotFoundError:
    print(f"⚠️ Hata: {dataset_path} bulunamadı!")
    exit()

# Her bir model için test döngüsü
for model_file in model_files:
    model_name = model_file.replace('.joblib', '')
    model_path = os.path.join(models_dir, model_file)
    
    try:
        model = joblib.load(model_path)
    except Exception as e:
        print(f"⚠️ {model_name} yüklenemedi: {e}")
        continue

    print("=" * 100)
    print(f"🤖 TEST EDİLEN MODEL: {model_name.upper()}")
    print("=" * 100)

    y_true = []
    y_pred = []
    skipped_counts = {'malicious': 0, 'benign': 0}

    categories = {
        0: normal_dir,
        1: webshell_dir
    }

    for true_label, category_dir in categories.items():
        if not os.path.exists(category_dir):
            continue

        for file_name in os.listdir(category_dir):
            file_path = os.path.join(category_dir, file_name)

            if os.path.isfile(file_path) and file_name.endswith('.php'):
                # Kopya kontrolü
                file_hash = calculate_md5(file_path)
                if file_hash in training_hashes:
                    origin_folder = training_hashes[file_hash]
                    skipped_counts[origin_folder] = skipped_counts.get(origin_folder, 0) + 1
                    continue
                
                # Özellik çıkarma
                features = extract_features(file_path, label=true_label)

                if features:
                    features_df = pd.DataFrame([features]).drop('label', axis=1)
                    
                    # HATA ÇÖZÜMÜ BURADA: Scaler.transform isimsiz bir dizi döndürür. 
                    # Biz o isimsiz diziyi, orijinal sütun isimleriyle bir DataFrame'e çeviriyoruz.
                    features_scaled = pd.DataFrame(scaler.transform(features_df), columns=feature_names)

                    # Model predict_proba destekliyor mu kontrol et
                    if hasattr(model, "predict_proba"):
                        probabilities = model.predict_proba(features_scaled)[0]
                        malicious_prob = probabilities[1]
                        prediction = 1 if malicious_prob >= PROBABILITY_THRESHOLD else 0
                    else:
                        prediction = model.predict(features_scaled)[0]
                    
                    y_true.append(true_label)
                    y_pred.append(prediction)

    total_skipped = sum(skipped_counts.values())

    if len(y_true) > 0:
        acc = accuracy_score(y_true, y_pred)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        malicious_count = sum(1 for p in y_pred if p == 1)
        benign_count = sum(1 for p in y_pred if p == 0)

        print(f"📊 {model_name} ÖZETİ:")
        print(f"   Tahmin Edilen Zararlı : {malicious_count}")
        print(f"   Tahmin Edilen Temiz   : {benign_count}")
        print(f"\n📈 PERFORMANS METRİKLERİ:")
        print(f"   Doğruluk (Accuracy)   : % {acc * 100:.2f}")
        print(f"   Kesinlik (Precision)  : % {precision * 100:.2f}")
        print(f"   Duyarlılık (Recall)   : % {recall * 100:.2f}")
        print(f"   F1-Skoru              : % {f1 * 100:.2f}")
        print(f"\n   Karmaşıklık Matrisi:")
        print(f"      TN: {cm[0][0]:<5} | FP: {cm[0][1]:<5}")
        print(f"      FN: {cm[1][0]:<5} | TP: {cm[1][1]:<5}")
        print("\n")
    else:
        print(f"⚠️ Test edilecek yepyeni dosya bulunamadı.\n")