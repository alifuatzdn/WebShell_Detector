import os
import joblib
import pandas as pd
from feature_extraction import extract_features, calculate_md5
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import warnings

# Suppress feature name warnings since the Pipeline handles them internally.
warnings.filterwarnings("ignore", category=UserWarning)

# Define absolute paths for the project structure.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
test_dir = os.path.join(BASE_DIR, "dataset", "external_data")
normal_dir = os.path.join(test_dir, "normal")
webshell_dir = os.path.join(test_dir, "webshell")
malicious_dir = os.path.join(BASE_DIR, "dataset", "malicious")
benign_dir = os.path.join(BASE_DIR, "dataset", "benign")

# Models directory where the saved Pipeline joblib files are located.
models_dir = os.path.join(BASE_DIR, "models")

# Probability threshold to classify a file as a webshell.
PROBABILITY_THRESHOLD = 0.60

# Build a hash map for files in a directory to detect duplicates
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


print("[INFO] Calculating hashes for training files to prevent data leakage...")
training_hashes = {}
training_hashes.update(get_hashes_from_dir(malicious_dir))
training_hashes.update(get_hashes_from_dir(benign_dir))
print(f"[OK] Found {len(training_hashes)} unique file hashes in the training set.\n")

# Verify the models directory exists.
if not os.path.exists(models_dir):
    print(f"[WARN] Models directory '{models_dir}' not found.")
    exit()

# Only target models saved as complete pipelines.
model_files = [f for f in os.listdir(models_dir) if f.endswith('_pipeline.joblib')]

if not model_files:
    print(f"[WARN] No pipeline models found in '{models_dir}'.")
    exit()

print(f"[INFO] Testing {len(model_files)} pipeline models...\n")

# List to store results for all models
all_results = []

# Iterate through each saved pipeline model to evaluate its performance.
for model_file in model_files:
    model_name = model_file.replace('_pipeline.joblib', '')
    model_path = os.path.join(models_dir, model_file)

    try:
        pipeline = joblib.load(model_path)
    except Exception as e:
        print(f"[WARN] Could not load {model_name}: {e}")
        continue

    print("=" * 100)
    print(f"[MODEL] TESTING: {model_name.upper()}")
    print("=" * 100)

    y_true = []
    y_pred = []
    skipped_counts = {'malicious': 0, 'benign': 0}

    # Map the true labels to their respective external directories.
    categories = {0: normal_dir, 1: webshell_dir}

    for true_label, category_dir in categories.items():
        if not os.path.exists(category_dir):
            continue

        for file_name in os.listdir(category_dir):
            file_path = os.path.join(category_dir, file_name)

            if os.path.isfile(file_path) and file_name.endswith(('.php', '.php.txt')):

                # Skip files that were already used during the training phase.
                file_hash = calculate_md5(file_path)
                if file_hash in training_hashes:
                    origin_folder = training_hashes[file_hash]
                    skipped_counts[origin_folder] = skipped_counts.get(origin_folder, 0) + 1
                    continue

                # Extract features from the external file.
                features = extract_features(file_path, label=true_label)

                if features:
                    # Pass raw data directly; the Pipeline handles the StandardScaler internally.
                    features_df = pd.DataFrame([features]).drop('label', axis=1)

                    # Extract the probability score if the model supports it.
                    if hasattr(pipeline, "predict_proba"):
                        probabilities = pipeline.predict_proba(features_df)[0]
                        malicious_prob = probabilities[1]
                        prediction = 1 if malicious_prob >= PROBABILITY_THRESHOLD else 0
                    else:
                        prediction = pipeline.predict(features_df)[0]

                    y_true.append(true_label)
                    y_pred.append(prediction)

    # Calculate and display metrics if valid test files were processed.
    if len(y_true) > 0:
        acc = accuracy_score(y_true, y_pred)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        malicious_count = sum(1 for p in y_pred if p == 1)
        benign_count = sum(1 for p in y_pred if p == 0)

        print(f"[SUMMARY] {model_name} RESULTS:")
        print(f"   Predicted Malicious : {malicious_count}")
        print(f"   Predicted Benign    : {benign_count}")
        print(f"   (Skipped Train Files: {sum(skipped_counts.values())})")
        print(f"\n[METRICS]")
        print(f"   Accuracy            : {acc * 100:.2f}%")
        print(f"   Precision           : {precision * 100:.2f}%")
        print(f"   Recall              : {recall * 100:.2f}%")
        print(f"   F1 Score            : {f1 * 100:.2f}%")
        print(f"\n   Confusion Matrix:")
        print(f"      TN: {cm[0][0]:<5} | FP: {cm[0][1]:<5}")
        print(f"      FN: {cm[1][0]:<5} | TP: {cm[1][1]:<5}")
        print("\n")
        
        # Save this model's metrics
        all_results.append({
            "Model": model_name,
            "Accuracy (%)": round(acc * 100, 2),
            "Precision (%)": round(precision * 100, 2),
            "Recall (%)": round(recall * 100, 2),
            "F1 Score (%)": round(f1 * 100, 2),
            "Predicted Malicious": malicious_count,
            "Predicted Benign": benign_count,
            "True Negatives (TN)": cm[0][0],
            "False Positives (FP)": cm[0][1],
            "False Negatives (FN)": cm[1][0],
            "True Positives (TP)": cm[1][1],
            "Total Test Files": len(y_true)
        })
    else:
        print("[WARN] No new external files found to test.\n")

# Save all gathered results to a CSV file.
if all_results:
    results_file_path = os.path.join(BASE_DIR, "external_test_results.csv")
    results_df = pd.DataFrame(all_results)
    
    # Check if the file already exists to decide whether to append or overwrite (here we overwrite for a fresh report)
    results_df.to_csv(results_file_path, index=False)
    
    print("=" * 100)
    print(f"[SUCCESS] All model test results successfully saved to: \n{results_file_path}")
    print("=" * 100 + "\n")