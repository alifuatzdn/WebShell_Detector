import pandas as pd
import os
import time
import warnings
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
import xgboost as xgb
import joblib

# Hide noisy warnings
warnings.filterwarnings("ignore")

# 1) Paths and folders
base_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(base_dir, "dataset", "webshell_features.csv")
models_dir = os.path.join(base_dir, "models")
scaler_path = os.path.join(base_dir, "scaler.joblib")

if not os.path.exists(models_dir):
    os.makedirs(models_dir)

# 2) Load and split the data
print("\n" + "="*70)
print("Model training and tuning is starting")
print("="*70)

try:
    df = pd.read_csv(data_path)
except FileNotFoundError:
    print(f"Error: {data_path} not found")
    exit()

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# StandardScaler while keeping original column names
scaler = StandardScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)

# Save the scaler
joblib.dump(scaler, scaler_path)
print("Scaler created and saved\n")

# 3) Models and search spaces with anti overfitting settings
models_to_train = {
    "LogisticRegression": {
        "model": LogisticRegression(random_state=42, max_iter=1000),
        "params": {
            'C': [0.01, 0.1, 1, 10, 100],
            'penalty': ['l2'],
            'class_weight': [None, 'balanced']
        }
    },
    "KNN": {
        "model": KNeighborsClassifier(),
        "params": {
            'n_neighbors': [3, 5, 7, 9],
            'weights': ['uniform', 'distance'],
            'p': [1, 2] # 1: Manhattan, 2: Euclidean
        }
    },
    "SVM": {
        "model": SVC(probability=True, random_state=42),
        "params": {
            'C': [0.1, 1, 10],
            'kernel': ['linear', 'rbf'],
            'gamma': ['scale', 'auto'],
            'class_weight': [None, 'balanced']
        }
    },
    "RandomForest": {
        "model": RandomForestClassifier(random_state=42),
        "params": {
            'n_estimators': [100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'class_weight': ['balanced', 'balanced_subsample']
        }
    },
    "XGBoost": {
        "model": xgb.XGBClassifier(random_state=42, eval_metric='logloss'),
        "params": {
            'n_estimators': [100, 200],
            'max_depth': [3, 5, 7],
            'learning_rate': [0.01, 0.05, 0.1],
            'subsample': [0.8, 1.0],
            'colsample_bytree': [0.8, 1.0],
            'scale_pos_weight': [1, 2, 5] 
        }
    }
}

# 4) Training, tuning, and saving loop
print(f"Training and tuning {len(models_to_train)} models\n")

for name, config in models_to_train.items():
    print(f"Training {name} and searching for best settings")
    start_time = time.time()
    
    model = config["model"]
    params = config["params"]
    
    # Try 10 random parameter combinations and keep the best
    search = RandomizedSearchCV(
        estimator=model,
        param_distributions=params,
        n_iter=10, 
        cv=3, 
        scoring='accuracy', 
        n_jobs=-1, 
        random_state=42,
        verbose=0
    )
    
    # Train the model
    search.fit(X_train_scaled, y_train)
    
    best_model = search.best_estimator_
    
    # Measure accuracy on the test set
    y_pred = best_model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    end_time = time.time()
    
    print(f"{name} done in {end_time - start_time:.1f}s | Test accuracy: {acc*100:.2f}%")

    # Save the tuned model
    model_file_path = os.path.join(models_dir, f"{name}.joblib")
    joblib.dump(best_model, model_file_path)

print("\n" + "="*70)
print(f"All models saved to '{models_dir}'")
print("Run 'external_data_test.py' to evaluate on external data")
print("="*70)