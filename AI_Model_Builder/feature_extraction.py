import os
import math
import hashlib
import random
import re
import pandas as pd
from tqdm import tqdm
from collections import Counter


# 1. ENTROPY HESAPLAMA (Daha hızlı yöntem)
def calculate_entropy(text):
    if not text: return 0
    counts = Counter(text)
    total = len(text)
    entropy = 0
    for count in counts.values():
        p_x = count / total
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

# MD5 HASH HESAPLAMA (Dosyanın içeriğinin benzersizliğini kontrol etmek için)
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

# 2. ÖZNİTELİK ÇIKARMA (REGEX ile daha güçlü yakalama)
def extract_features(file_path, label):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        features = {}
        # 1. YAPISAL ÖZELLİKLER
        features['entropy'] = calculate_entropy(content)
        features['file_length'] = len(content)
        features['max_line_length'] = max([len(line) for line in lines]) if lines else 0
        features['nb_lines'] = len(lines)

        # 2. TEHLİKELİ FONKSİYONLAR (EXECUTION & ENCODING)
        features['eval_count'] = content.count('eval(') + content.count('assert(') + content.count('create_function(') + content.count('preg_replace(')
        features['exec_count'] = content.count('shell_exec(') + content.count('system(') + content.count(
            'exec(') + content.count('passthru(') + content.count('popen(') + content.count('proc_open(')
        features['obfuscation_count'] = content.count('base64_decode(') + content.count('str_rot13(') + content.count(
            'gzinflate(') + content.count('unserialize(') + content.count('gzuncompress(') + content.count('strrev(')

        # 3. DOSYA/SİSTEM MANİPÜLASYONU
        features['fs_count'] = content.count('chmod(') + content.count('fopen(') + content.count('file_put_contents(')

        # 4. DIŞARIDAN VERİ ALMA (SUPERGLOBALS)
        features['network_input_count'] = content.count('$_POST') + content.count('$_GET') + content.count(
            '$_REQUEST') + content.count('$_COOKIE') + content.count('$_SERVER') + content.count('$_FILES')

        # ---------------------------------------------------------
        # YENİ ÖZELLİKLER (GELİŞMİŞ TESPİT)
        # ---------------------------------------------------------
        
        # 5. ÖZEL KARAKTER YOĞUNLUĞU (Obfuscated / Karıştırılmış kod tespiti)
        # Web shell'lerde genellikle ; , (, ), {, }, [, ], $, @, \ vb. çok sık görülür.
        special_chars = re.findall(r'[^a-zA-Z0-9\s]', content)
        features['special_char_ratio'] = len(special_chars) / len(content) if len(content) > 0 else 0

        # 6. ANLAMSIZ / UZUN DEĞİŞKEN İSİMLERİ (Örn: $O00OO0, $x123_y)
        # Normal programcılar değişkenlere anlamlı isim verir ($user_id gibi).
        # Ancak shell'ler saklanmak için rastgele uzun değişkenler kullanır.
        variables = re.findall(r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*', content)
        if variables:
            avg_var_length = sum(len(var) for var in variables) / len(variables)
            # Kaç tane değişkenin adı 10 karakterden uzun?
            long_vars = sum(1 for var in variables if len(var) > 10)
        else:
            avg_var_length = 0
            long_vars = 0
            
        features['avg_var_length'] = avg_var_length
        features['long_vars_count'] = long_vars

        # 7. BOŞLUK (WHITESPACE) ORANI
        # Zararlı dosyalar (minify edilmemişse) boşluksuz uzun satırlardan oluşabilir.
        whitespaces = sum(1 for char in content if char.isspace())
        features['whitespace_ratio'] = whitespaces / len(content) if len(content) > 0 else 0

        features['label'] = label
        return features
    except Exception as e:
        return None


# 3. KLASÖR TARAMA
def process_directory(directory_path, label, seen_hashes):
    data = []
    skipped_count = 0
    
    # Klasördeki dosyaları al
    file_list = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]

    for file_name in tqdm(file_list, desc=f"İşleniyor ({'Zararlı' if label == 1 else 'Zararsız'})"):
        file_path = os.path.join(directory_path, file_name)
        
        # Benzersizliği kontrol et (MD5 hash ile)
        file_hash = calculate_md5(file_path)
        if file_hash is None or file_hash in seen_hashes:
            skipped_count += 1
            continue
        
        seen_hashes.add(file_hash)

        # Özellikleri çıkar
        file_features = extract_features(file_path, label)
        if file_features is not None:
            data.append(file_features)
            
    return data, skipped_count


if __name__ == "__main__":
    malicious_dir = "dataset/malicious"
    benign_dir = "dataset/benign"

    print("Veri analizi başlıyor (Benzersiz dosyalar filtreleniyor)...")

    seen_hashes = set()
    
    malicious_data, mal_skipped = process_directory(malicious_dir, label=1, seen_hashes=seen_hashes)
    benign_data, ben_skipped = process_directory(benign_dir, label=0, seen_hashes=seen_hashes)
    
    print("-" * 50)
    print(f"Malicious klasöründe atlanan (kopya) dosya sayısı: {mal_skipped}")
    print(f"Benign klasöründe atlanan (kopya) dosya sayısı   : {ben_skipped}")
    print("-" * 50)

    # Undersampling (Dengeleme)
    mal_count = len(malicious_data)
    ben_count = len(benign_data)
    
    print(f"Benzersiz Zararlı Dosya Sayısı : {mal_count}")
    print(f"Benzersiz Zararsız Dosya Sayısı: {ben_count}")
    
    min_count = min(mal_count, ben_count)
    
    if mal_count > min_count:
        print(f"Zararlı veri seti daha büyük. Undersampling yapılıyor ({mal_count} -> {min_count})...")
        # Rastgelelik için seed belirlenebilir (tekrarlanabilirlik için: random.seed(42))
        random.seed(42) 
        malicious_data = random.sample(malicious_data, min_count)
    elif ben_count > min_count:
        print(f"Zararsız veri seti daha büyük. Undersampling yapılıyor ({ben_count} -> {min_count})...")
        random.seed(42)
        benign_data = random.sample(benign_data, min_count)
    else:
        print("Veri seti zaten dengeli.")

    print("-" * 50)
    
    all_data = malicious_data + benign_data

    df = pd.DataFrame(all_data)

    output_file = "dataset/webshell_features.csv"
    df.to_csv(output_file, index=False)

    print(f"\nİşlem tamamlandı! Toplam {len(df)} dosya analiz edilip veri setine eklendi (Dengeli Set: {min_count} Zararlı / {min_count} Zararsız).")
    print(f"Yeni özelliklerle {output_file} güncellendi.")