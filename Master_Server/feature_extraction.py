import os
import math
import hashlib
import random
import re
import pandas as pd
from tqdm import tqdm
from collections import Counter


# Entropy calculation with a fast method
def calculate_entropy(text):
    if not text: return 0
    counts = Counter(text)
    total = len(text)
    entropy = 0
    for count in counts.values():
        p_x = count / total
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)


# MD5 hash calculation to check file uniqueness
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None


# Feature extraction with regex helpers
def extract_features(file_path, label):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        features = {}
        # Structural features
        features['entropy'] = calculate_entropy(content)
        features['file_length'] = len(content)
        features['max_line_length'] = max([len(line) for line in lines]) if lines else 0
        features['nb_lines'] = len(lines)

        # Risky functions for execution and encoding
        features['eval_count'] = content.count('eval(') + content.count('assert(') + content.count(
            'create_function(') + content.count('preg_replace(')
        features['exec_count'] = content.count('shell_exec(') + content.count('system(') + content.count(
            'exec(') + content.count('passthru(') + content.count('popen(') + content.count('proc_open(')
        features['obfuscation_count'] = content.count('base64_decode(') + content.count('str_rot13(') + content.count(
            'gzinflate(') + content.count('unserialize(') + content.count('gzuncompress(') + content.count('strrev(')

        # File and system manipulation
        features['fs_count'] = content.count('chmod(') + content.count('fopen(') + content.count('file_put_contents(')

        # External input use via superglobals
        features['network_input_count'] = content.count('$_POST') + content.count('$_GET') + content.count(
            '$_REQUEST') + content.count('$_COOKIE') + content.count('$_SERVER') + content.count('$_FILES')

        # Special character density for obfuscated code
        special_chars = re.findall(r'[^a-zA-Z0-9\s]', content)
        features['special_char_ratio'] = round((len(special_chars) / len(content)), 5) if len(content) > 0 else 0

        # Long or random variable names like $O00OO0, $x123_y
        variables = re.findall(r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*', content)
        if variables:
            avg_var_length = sum(len(var) for var in variables) / len(variables)
            # Count how many variables are longer than 10 characters
            long_vars = sum(1 for var in variables if len(var) > 10)
        else:
            avg_var_length = 0
            long_vars = 0

        features['avg_var_length'] = round(avg_var_length, 5)
        features['long_vars_count'] = long_vars

        # Whitespace ratio
        whitespaces = sum(1 for char in content if char.isspace())
        features['whitespace_ratio'] = round((whitespaces / len(content)), 5) if len(content) > 0 else 0

        features['label'] = label
        return features
    except Exception as e:
        return None


# Directory scan
def process_directory(directory_path, label, seen_hashes):
    data = []
    skipped_count = 0

    # List files in the directory
    file_list = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]

    for file_name in tqdm(file_list, desc=f"Processing ({'Malicious' if label == 1 else 'Benign'})"):
        file_path = os.path.join(directory_path, file_name)

        # Check uniqueness with MD5
        file_hash = calculate_md5(file_path)
        if file_hash is None or file_hash in seen_hashes:
            skipped_count += 1
            continue

        seen_hashes.add(file_hash)

        # Extract features
        file_features = extract_features(file_path, label)
        if file_features is not None:
            data.append(file_features)

    return data, skipped_count


if __name__ == "__main__":
    malicious_dir = "dataset/malicious"
    benign_dir = "dataset/benign"

    print("Starting data analysis, filtering duplicate files")

    seen_hashes = set()

    malicious_data, mal_skipped = process_directory(malicious_dir, label=1, seen_hashes=seen_hashes)
    benign_data, ben_skipped = process_directory(benign_dir, label=0, seen_hashes=seen_hashes)

    print("-" * 50)
    print(f"Skipped duplicates in malicious folder: {mal_skipped}")
    print(f"Skipped duplicates in benign folder   : {ben_skipped}")
    print("-" * 50)

    # Undersampling for balance
    mal_count = len(malicious_data)
    ben_count = len(benign_data)

    print(f"Unique malicious files: {mal_count}")
    print(f"Unique benign files   : {ben_count}")

    min_count = min(mal_count, ben_count)

    if mal_count > min_count:
        print(f"Malicious set is larger, undersampling ({mal_count} -> {min_count})")
        # Set a seed for repeatable sampling
        random.seed(42)
        malicious_data = random.sample(malicious_data, min_count)
    elif ben_count > min_count:
        print(f"Benign set is larger, undersampling ({ben_count} -> {min_count})")
        random.seed(42)
        benign_data = random.sample(benign_data, min_count)
    else:
        print("Dataset is already balanced")

    print("-" * 50)

    all_data = malicious_data + benign_data

    df = pd.DataFrame(all_data)

    output_file = "dataset/webshell_features.csv"
    df.to_csv(output_file, index=False)

    print(f"\nDone, analyzed {len(df)} files and updated the dataset")
    print(f"Balanced set: {min_count} malicious / {min_count} benign")
    print(f"Saved to {output_file}")
