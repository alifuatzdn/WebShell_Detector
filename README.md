# WebShell Detector

An automated web shell detection and management system using machine learning. The system monitors file uploads, analyzes PHP files for malicious patterns, and enforces security policies including IP blocking and quarantine.

## 🏗️ Architecture

The system consists of three main components:

### 1. **Master Server** (`Master_Server/`)
- Central analysis engine using XGBoost ML model
- Analyzes uploaded PHP files for web shell signatures
- Returns risk probability and malicious/benign classification
- Runs on port `5000`

### 2. **Agent Node** (`Agent_Node/`)
- File system watcher that monitors directories
- Sends suspicious files to Master Server for analysis
- Quarantines detected malicious files
- Implements attacker IP blocking (iptables/ban list)
- Web-based upload interface on port `8000`

### 3. **AI Model Builder** (`AI_Model_Builder/`)
- Feature extraction pipeline for PHP file analysis
- Dataset management (benign & malicious samples)
- Model training and tuning scripts
- Pre-trained models (XGBoost, LogisticRegression, SVM, KNN, RandomForest)

## 🚀 Quick Start

### Prerequisites
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Note: `markupsafe` is required for Flask template rendering

### Dependency Check
To verify your local environment against `requirements.txt`:
```bash
python3 tools/check_requirements.py
```
This reports missing or outdated packages before running the server or training scripts.

### Running the System (Same Machine)

**Terminal 1 - Master Server (Analysis Engine):**
```bash
cd Master_Server
python server.py
```

**Terminal 2 - Agent Node (File Monitor):**
```bash
cd Agent_Node
python agent.py
```

**Terminal 3 - Upload Web Service:**
```bash
cd Agent_Node
python upload_server.py
```

### Remote Connection (Same Network)

Edit `Agent_Node/agent.py` line 173 to use the server's LAN IP:
```python
SERVER_URL = "http://172.28.154.59:5000/analyze"  # Replace with actual IP
```

Then access the upload interface from another machine:
```
http://172.28.154.59:8000
```

## 📁 Project Structure

```
WebShell_Detector/
├── Agent_Node/
│   ├── agent.py              # File system watcher & attacker IP blocker
│   ├── upload_server.py      # Web upload interface (port 8000)
│   ├── access.log            # Access logs for IP tracking
│   ├── banned_ips.txt        # Banned IP addresses
│   ├── test_www/             # Directory to monitor for new PHP files
│   └── quarantine/           # Isolated malicious files
│
├── Master_Server/
│   ├── server.py             # Flask API for file analysis (port 5000)
│   └── feature_extraction.py # Feature extraction utilities
│
├── AI_Model_Builder/
│   ├── train_and_tune_models.py    # Model training script
│   ├── feature_extraction.py       # Feature extraction logic
│   ├── external_data_test.py       # External dataset testing
│   ├── scaler.joblib               # Fitted StandardScaler
│   ├── models/                     # Pre-trained ML models
│   │   ├── XGBoost.joblib
│   │   ├── LogisticRegression.joblib
│   │   ├── SVM.joblib
│   │   ├── KNN.joblib
│   │   └── RandomForest.joblib
│   └── dataset/
│       ├── webshell_features.csv    # Feature dataset
│       ├── benign/                  # Legitimate PHP files
│       └── malicious/               # Web shell samples
│
└── README.md
```

## 🔧 Configuration

### Server URL (Agent Connection)
**Default (localhost):**
```python
SERVER_URL = "http://127.0.0.1:5000/analyze"
```

**For same network (from different machine):**
```python
SERVER_URL = "http://<ACTUAL_IP>:5000/analyze"
```

### ML Model Selection
Edit `Master_Server/server.py` line 20:
```python
MODEL_NAME = "XGBoost.joblib"  # Options: XGBoost, LogisticRegression, SVM, KNN, RandomForest
```

### Detection Threshold
Adjust probability threshold in `Master_Server/server.py` line 24:
```python
PROBABILITY_THRESHOLD = 0.50  # Range: 0.0 to 1.0
```

## 🛡️ Security Features

### File Analysis
- **Entropy calculation** - Detects obfuscated/compressed code
- **Dangerous functions** - Identifies `eval()`, `shell_exec()`, `system()`, etc.
- **Obfuscation patterns** - Detects `base64_decode()`, `gzinflate()`, etc.
- **Special character density** - Finds suspicious code patterns
- **Variable naming analysis** - Detects meaningless variable names
- **Network input tracking** - Monitors `$_POST`, `$_GET`, `$_REQUEST`, etc.

### IP Blocking
- Automatic ban list (`banned_ips.txt`)
- iptables integration (on Linux with root privileges)
- Web upload rejection for banned IPs (HTTP 403)
- Persistent ban storage

### File Isolation
- Automatic quarantine of detected threats (chmod 000)
- Original file path preserved in logs
- Safe temporary file handling

## 📊 Feature Extraction

Extracted features from PHP files:
- `entropy` - Shannon entropy of file content
- `file_length` - Total bytes
- `max_line_length` - Longest line in file
- `nb_lines` - Number of lines
- `eval_count` - Count of dangerous eval-type functions
- `exec_count` - Count of execution functions
- `obfuscation_count` - Count of encoding functions
- `fs_count` - File system operation functions
- `network_input_count` - SuperGlobal usage
- `special_char_ratio` - Density of special characters
- `avg_var_length` - Average variable name length
- `long_vars_count` - Count of abnormally long variable names
- `whitespace_ratio` - Code formatting density

## 🔌 API Endpoints

### Master Server
**POST `/analyze`**
- Accepts multipart file upload
- Returns JSON with status, probability, and message

**Response (Malicious):**
```json
{
  "status": "MALICIOUS",
  "probability": 0.87,
  "message": "Webshell tespit edildi!"
}
```

**Response (Benign):**
```json
{
  "status": "BENIGN",
  "probability": 0.12,
  "message": "Dosya temiz."
}
```

### Agent Web Interface
**GET/POST `/`** - File upload form on port 8000
- Accepts `.php` files
- Shows upload status
- Rejects banned IPs with 403 error

## 📝 Logs

### Access Log (`Agent_Node/access.log`)
Apache-format access logs for IP tracking:
```
192.168.1.5 - - [24/May/2026:14:32:10 +0300] "POST /upload HTTP/1.1" 200 sample.php
```

### Ban List (`Agent_Node/banned_ips.txt`)
Newline-separated list of blocked IPs:
```
192.168.1.10
10.0.0.50
```

### Console Output
Both services print real-time analysis results:
```
🚨 [ALARM] Zararlı dosya tespit edildi: shell.php (Olasılık: %92.5)
✅ [BİLGİ] Temiz dosya: config.php
🎯 HEDEF(LER) BULUNDU! Saldırgan IP'leri: 192.168.1.5
🧱 FIREWALL: 192.168.1.5 adresi sistemden tamamen engelleniyor...
```

## ⚙️ Event Handling

### Duplicate Event Suppression
- File creation/modification events are debounced (1.5s cooldown)
- Prevents duplicate analysis for temporary file writes

### Ban Enforcement
First request from IP that uploads malicious file is analyzed normally. If malicious:
1. File name is logged
2. IP extracted from access log
3. IP added to `banned_ips.txt`
4. Subsequent uploads from that IP rejected (403)

## 🛠️ Development

### Training Models
```bash
cd AI_Model_Builder
python train_and_tune_models.py
```

### Testing with External Data
```bash
cd AI_Model_Builder
python external_data_test.py
```

## 📋 System Requirements

- Python 3.8+
- Linux/macOS (iptables support for IP blocking on Linux)
- 500MB+ free disk space (for models & datasets)
- RAM: 2GB+ recommended
- Network: Open ports 5000 (analysis) and 8000 (uploads)

## 🔐 Security Considerations

- **Do NOT expose** port 5000/8000 directly to untrusted networks without authentication
- **Use firewall rules** to restrict access to trusted IPs only
- **Run with appropriate permissions** (non-root preferred, root only for iptables)
- **Monitor disk space** for quarantine directory growth
- **Regularly review** ban list and logs
- **Update models** with new samples for threat evolution
