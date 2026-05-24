import os
import shutil
import subprocess
import time
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class WebShellAgent(FileSystemEventHandler):
    def __init__(self, server_url, watch_dir, quarantine_dir, log_file):
        self.server_url = server_url
        self.watch_dir = watch_dir
        self.quarantine_dir = quarantine_dir
        self.log_file = log_file
        self.banned_ips_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banned_ips.txt")
        self.event_cooldown = 1.5
        self._recent_events = {}

    def _should_skip_event(self, file_path):
        now = time.time()
        last_seen = self._recent_events.get(file_path, 0)
        if now - last_seen < self.event_cooldown:
            return True
        self._recent_events[file_path] = now
        return False

    def load_banned_ips(self):
        if not os.path.exists(self.banned_ips_file):
            return set()

        with open(self.banned_ips_file, "r") as f:
            return {line.strip() for line in f if line.strip()}

    def register_ban(self, ip_address):
        banned_ips = self.load_banned_ips()
        if ip_address in banned_ips:
            return False

        with open(self.banned_ips_file, "a") as f:
            f.write(f"{ip_address}\n")

        return True

    def on_created(self, event):
        if event.is_directory:
            return

        event_path = str(event.src_path)
        if event_path.endswith('.php'):
            print(f"\n[!] Yeni dosya tespit edildi: {os.path.basename(event_path)}")
            self.send_to_server(event_path)

    def on_modified(self, event):
        if event.is_directory:
            return

        event_path = str(event.src_path)
        if event_path.endswith('.php'):
            print(f"\n[!] Dosya değiştirildi: {os.path.basename(event_path)}")
            self.send_to_server(event_path)

    def send_to_server(self, file_path):
        if self._should_skip_event(file_path):
            print(f"⏭️ Yinelenen olay atlandı: {os.path.basename(file_path)}")
            return

        time.sleep(0.5)  # Dosyanın tam yazılması için bekle

        try:
            print(f"📡 Merkez sunucuya gönderiliyor... ({self.server_url})")
            
            # Dosyayı "Gerçekten" sunucuya yolluyoruz (İçeriğiyle birlikte)
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(str(file_path)), f.read(), 'application/octet-stream')}
                response = requests.post(self.server_url, files=files, timeout=5)

            if response.status_code == 200:
                result = response.json()
                status = result.get("status")
                
                if status == "MALICIOUS":
                    print(f"🚨 MERKEZ KARARI: ZARARLI (Olasılık: %{result.get('probability', 0)*100:.1f})")
                    self.quarantine_file(file_path)
                    self.hunt_attacker(file_path)
                elif status == "BENIGN":
                    print(f"✅ MERKEZ KARARI: TEMİZ")
            else:
                print(f"⚠️ Sunucu Hatası: {response.text}")

        except requests.exceptions.ConnectionError:
            print("❌ HATA: Merkez Sunucuya bağlanılamadı. Sunucu kapalı olabilir.")
        except Exception as e:
            print(f"❌ Beklenmeyen Hata: {e}")

    def quarantine_file(self, file_path):
        try:
            file_name = os.path.basename(str(file_path))
            destination = os.path.join(self.quarantine_dir, file_name)
            shutil.move(str(file_path), destination)
            os.chmod(destination, 0o000)
            print(f"🛡️ EYLEM: Dosya karantinaya alındı -> {destination}")
        except Exception as e:
            print(f"⚠️ Karantina hatası: {e}")

    # LOG OKUMA VE IP BULMA FONKSİYONU
    def hunt_attacker(self, file_path):
        file_name = os.path.basename(str(file_path))
        print(f"🔍 İstihbarat: '{file_name}' dosyasını yükleyen IP(ler) aranıyor...")

        found_ips = set()
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()

                for line in reversed(lines):
                    if file_name in line:
                        attacker_ip = line.split(' ')[0]
                        found_ips.add(attacker_ip)
            
            if found_ips:
                print(f"🎯 HEDEF(LER) BULUNDU! Saldırgan IP'leri: {', '.join(found_ips)}")
                for ip in found_ips:
                    self.block_ip(ip)
            else:
                print("⚠️ Log dosyasında bu dosyaya ait bir kayıt bulunamadı.")
        except FileNotFoundError:
            print(f"⚠️ Log dosyası bulunamadı: {self.log_file}")

    # GÜVENLİK DUVARI (FIREWALL) ENGELLEME FONKSİYONU
    def block_ip(self, ip_address):
        print(f"🧱 FIREWALL: {ip_address} adresi sistemden tamamen engelleniyor...")
        try:
            added_to_ban_list = self.register_ban(ip_address)

            is_posix_root = os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0

            if is_posix_root:
                existing_rule = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                    capture_output=True,
                    text=True,
                )

                if existing_rule.returncode == 0:
                    print(f"   ℹ️ Zaten mevcut firewall kuralı: {ip_address}")
                else:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    print(f"   ✅ BAŞARILI KURAL: iptables -I INPUT -s {ip_address} -j DROP")
            else:
                if added_to_ban_list:
                    print(f"   ✅ IP ban listesine yazıldı: {self.banned_ips_file}")
                else:
                    print(f"   ℹ️ IP zaten banlıydı: {ip_address}")
                print("   ⚠️ iptables uygulanmadı (root izni veya komut bulunamadı).")
        except Exception as e:
            print(f"❌ Firewall kuralı eklenemedi: {e}")


if __name__ == "__main__":
    # SADECE AGENT_NODE KLASÖRÜNÜ KULLANACAK ŞEKİLDE DÜZELTİLDİ
    AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
    watch_dir = os.path.join(AGENT_DIR, "test_www")
    quarantine_dir = os.path.join(AGENT_DIR, "quarantine")
    log_file = os.path.join(AGENT_DIR, "access.log")
    
    # Merkez sunucu API adresi
    SERVER_URL = "http://172.28.154.59:5000/analyze"

    os.makedirs(watch_dir, exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)

    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write("192.168.1.5 - - [24/May/2026:14:32:10 +0300] \"POST /upload.php HTTP/1.1\" 200\n")

    if not os.path.exists(os.path.join(AGENT_DIR, "banned_ips.txt")):
        with open(os.path.join(AGENT_DIR, "banned_ips.txt"), 'w') as f:
            f.write("")

    event_handler = WebShellAgent(SERVER_URL, watch_dir, quarantine_dir, log_file)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=True)

    print(f"👀 Ajan aktif. '{watch_dir}' klasörü izleniyor...")
    print(f"📡 Merkez Sunucu: {SERVER_URL}")
    print("Çıkış yapmak için CTRL+C tuşlarına bas.")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()