import os
import shutil
import subprocess
import time
import requests
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class WebShellAgent(FileSystemEventHandler):
    # Initialize agent configuration and state
    def __init__(self, server_url, watch_dir, quarantine_dir, log_file):
        self.server_url = server_url
        self.watch_dir = watch_dir
        self.quarantine_dir = quarantine_dir
        self.log_file = log_file
        self.banned_ips_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banned_ips.txt")
        self.event_cooldown = 1.5
        self._recent_events = {}

    # Skip repeated events for the same file in a short time window
    def _should_skip_event(self, file_path):
        now = time.time()
        last_seen = self._recent_events.get(file_path, 0)
        if now - last_seen < self.event_cooldown:
            return True
        self._recent_events[file_path] = now
        return False

    # Load banned IPs from the local list file
    def load_banned_ips(self):
        if not os.path.exists(self.banned_ips_file):
            return set()

        with open(self.banned_ips_file, "r") as f:
            return {line.strip() for line in f if line.strip()}

    # Add an IP to the local ban list if it is not already present
    def register_ban(self, ip_address):
        banned_ips = self.load_banned_ips()
        if ip_address in banned_ips:
            return False

        with open(self.banned_ips_file, "a") as f:
            f.write(f"{ip_address}\n")

        return True

    # Handle newly created files
    def on_created(self, event):
        if event.is_directory:
            return

        event_path = str(event.src_path)
        if event_path.endswith('.php'):
            print(f"\nNew file detected: {os.path.basename(event_path)}")
            self.send_to_server(event_path)

    # Handle modified files
    def on_modified(self, event):
        if event.is_directory:
            return

        event_path = str(event.src_path)
        if event_path.endswith('.php'):
            print(f"\nFile modified: {os.path.basename(event_path)}")
            self.send_to_server(event_path)

    # Send a file to the central server for analysis
    def send_to_server(self, file_path):
        if self._should_skip_event(file_path):
            print(f"[SKIP] Skipping duplicate event: {os.path.basename(file_path)}")
            return

        time.sleep(0.5)  # Wait for the file write to finish

        try:
            print(f"[SEND] Sending to server ({self.server_url})")

            # Send file contents to the server
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(str(file_path)), f.read(), 'application/octet-stream')}
                response = requests.post(self.server_url, files=files, timeout=5)

            if response.status_code == 200:
                result = response.json()
                status = result.get("status")

                if status == "MALICIOUS":
                    probability = result.get('probability', 0) * 100
                    print(f"[ALERT] Central result: malicious ({probability:.1f}%)")
                    self.quarantine_file(file_path)
                    self.hunt_attacker(file_path)
                elif status == "BENIGN":
                    print("[OK] Central result: clean")
            else:
                print(f"[WARN] Server error: {response.text}")

        except requests.exceptions.ConnectionError:
            print("[ERROR] Could not connect to the server, it may be offline")
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

    # Move a malicious file into quarantine and lock its permissions
    def quarantine_file(self, file_path):
        try:
            file_name = os.path.basename(str(file_path))
            destination = os.path.join(self.quarantine_dir, file_name)
            shutil.move(str(file_path), destination)
            os.chmod(destination, 0o000)
            print(f"[ACTION] File quarantined -> {destination}")
        except Exception as e:
            print(f"[WARN] Quarantine error: {e}")

    # Search logs for the IPs that uploaded the suspicious file
    def hunt_attacker(self, file_path):
        file_name = os.path.basename(str(file_path))
        print(f"[INTEL] Looking for IPs that uploaded '{file_name}'")

        found_ips = set()
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()

                for line in reversed(lines):
                    if file_name in line:
                        attacker_ip = line.split(' ')[0]
                        found_ips.add(attacker_ip)

            if found_ips:
                print(f"[FOUND] Attacker IPs: {', '.join(found_ips)}")
                for ip in found_ips:
                    self.block_ip(ip)
            else:
                print("[WARN] No log entry found for this file")
        except FileNotFoundError:
            print(f"[WARN] Log file not found: {self.log_file}")

    # Block an IP via firewall if possible and record it locally
    def block_ip(self, ip_address):
        print(f"[FIREWALL] Blocking {ip_address} on this system")
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
                    print(f"   [INFO] Firewall rule already exists: {ip_address}")
                else:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    print(f"   [OK] Rule added: iptables -I INPUT -s {ip_address} -j DROP")
            else:
                if added_to_ban_list:
                    print(f"   [OK] IP added to ban list: {self.banned_ips_file}")
                else:
                    print(f"   [INFO] IP already banned: {ip_address}")
                print("   [WARN] iptables not applied (missing root permissions or command)")
        except Exception as e:
            print(f"[ERROR] Failed to add firewall rule: {e}")


if __name__ == "__main__":
    # Use the Agent_Node folder as the runtime base
    AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(AGENT_DIR)
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
    watch_dir = os.getenv("WATCH_DIR", os.path.join(AGENT_DIR, "test_www"))
    quarantine_dir = os.getenv("QUARANTINE_DIR", os.path.join(AGENT_DIR, "quarantine"))
    log_file = os.getenv("LOG_FILE", os.path.join(AGENT_DIR, "access.log"))

    # Set these manually for the machine running Master_Server
    SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
    SERVER_PORT = os.getenv("SERVER_PORT", "5000")
    SERVER_URL = os.getenv("SERVER_URL", f"http://{SERVER_HOST}:{SERVER_PORT}/analyze")
    EVENT_COOLDOWN = float(os.getenv("EVENT_COOLDOWN", "1.5"))

    os.makedirs(watch_dir, exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)

    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write("192.168.1.5 - - [24/May/2026:14:32:10 +0300] \"POST /upload.php HTTP/1.1\" 200\n")

    if not os.path.exists(os.path.join(AGENT_DIR, "banned_ips.txt")):
        with open(os.path.join(AGENT_DIR, "banned_ips.txt"), 'w') as f:
            f.write("")

    event_handler = WebShellAgent(SERVER_URL, watch_dir, quarantine_dir, log_file)
    event_handler.event_cooldown = EVENT_COOLDOWN
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=True)

    print(f"[WATCH] Agent active, watching: '{watch_dir}'")
    print(f"[SERVER] Central server: {SERVER_URL}")
    print(f"[TIP] Change SERVER_HOST or SERVER_URL with environment variables if needed")
    print("Press CTRL+C to exit")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()