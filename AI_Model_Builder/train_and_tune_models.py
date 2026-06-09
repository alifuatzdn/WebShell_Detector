import pandas as pd
import os
import time
import warnings
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
import xgboost as xgb
import joblib

# Suppress verbose warnings to keep the terminal output clean during optimization.
warnings.filterwarnings("ignore")

# Define absolute directory paths to ensure the script runs correctly from anywhere.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "dataset", "webshell_features.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Create the models directory automatically if it does not already exist.
os.makedirs(MODELS_DIR, exist_ok=True)

print("Starting Model Training & Tuning...\n")

# Load the dataset safely and exit with an error message if the file is missing.
try:
    df = pd.read_csv(DATA_PATH)
except FileNotFoundError:
    print(f"Error: {DATA_PATH} not found!")
    exit()

# Separate the independent features (X) from the target classification labels (y).
X = df.drop('label', axis=1)
y = df['label']

# Split the data while preserving the balanced class distribution via stratify.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Define models within Pipelines to prevent data leakage during cross-validation.
models_to_train = {
    "LogisticRegression": {
        "pipeline": Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', LogisticRegression(random_state=42, max_iter=2000, solver='saga'))
        ]),
        # Define hyperparameter spaces prefixed with 'classifier__' for the Pipeline.
        "params": {
            'classifier__C': [0.001, 0.01, 0.1, 1, 10, 100],
            'classifier__penalty': ['l1', 'l2'],
            'classifier__class_weight': [None, 'balanced']
        }
    },
    "KNN": {
        "pipeline": Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', KNeighborsClassifier())
        ]),
        "params": {
            'classifier__n_neighbors': [3, 5, 7, 9, 11, 15],
            'classifier__weights': ['uniform', 'distance'],
            'classifier__p': [1, 2]
        }
    },
    "SVM": {
        "pipeline": Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', SVC(probability=True, random_state=42))
        ]),
        "params": {
            'classifier__C': [0.1, 1, 10, 50, 100],
            'classifier__kernel': ['linear', 'rbf'],
            'classifier__gamma': ['scale', 'auto', 0.1, 0.01],
            'classifier__class_weight': [None, 'balanced']
        }
    },
    "RandomForest": {
        "pipeline": Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(random_state=42))
        ]),
        "params": {
            'classifier__n_estimators': [100, 200, 300, 500],
            'classifier__max_depth': [None, 10, 20, 30],
            'classifier__min_samples_split': [2, 5, 10],
            'classifier__min_samples_leaf': [1, 2, 4],
            'classifier__bootstrap': [True, False]
        }
    },
    "XGBoost": {
        "pipeline": Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', xgb.XGBClassifier(random_state=42, eval_metric='logloss'))
        ]),
        "params": {
            'classifier__n_estimators': [100, 200, 300, 500],
            'classifier__max_depth': [3, 5, 7, 9],
            'classifier__learning_rate': [0.01, 0.05, 0.1, 0.2],
            'classifier__subsample': [0.6, 0.8, 1.0],
            'classifier__colsample_bytree': [0.6, 0.8, 1.0]
        }
    }
}

# Iterate through each defined model to optimize and evaluate its performance.
for name, config in models_to_train.items():
    print(f"Optimizing {name}...")
    start_time = time.time()

    # Optimize using 30 random parameter combinations evaluated via 5-fold CV on F1-score.
    search = RandomizedSearchCV(
        estimator=config["pipeline"],
        param_distributions=config["params"],
        n_iter=30,
        cv=5,
        scoring='f1',
        n_jobs=-1,
        random_state=42,
        verbose=0
    )

    # Fit the search model directly on raw training data without manual scaling.
    search.fit(X_train, y_train)
    best_pipeline = search.best_estimator_

    # Evaluate the optimized pipeline on the isolated validation set.
    y_pred = best_pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f" -> Done in {time.time() - start_time:.1f}s")
    print(f" -> Val Acc: {acc * 100:.2f}% | Val F1: {f1:.4f}\n")

    # Save the complete pipeline containing both the scaler and the tuned model.
    model_file_path = os.path.join(MODELS_DIR, f"{name}_pipeline.joblib")
    joblib.dump(best_pipeline, model_file_path)

print("All models have been successfully tuned and saved.")