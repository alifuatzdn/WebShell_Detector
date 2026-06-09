import os
import shutil
import subprocess
import time
import requests
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv


class SecurityAgent(FileSystemEventHandler):
    """
    Monitors a staging directory, sends new files for AI analysis,
    and quarantines malicious uploads while actively banning attackers.
    """

    def __init__(self, server_url, staging_dir, www_dir, quarantine_dir, log_file, ban_file):
        self.server_url = server_url
        self.staging_dir = Path(staging_dir)
        self.www_dir = Path(www_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.log_file = Path(log_file)
        self.ban_file = Path(ban_file)

    def on_created(self, event):
        # Ignore directory creations and only process PHP or TXT files.
        if not event.is_directory and event.src_path.endswith(('.php', '.txt')):
            self.process_file(Path(event.src_path))

    def process_file(self, filepath: Path):
        # Introduce a slight delay to ensure the OS completes the file write operation.
        time.sleep(0.5)

        attacker_ip = "127.0.0.1"

        # Parse the access log backwards to extract the true IP of the uploader.
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            for line in reversed(lines):
                if f'"{filepath.name}"' in line:
                    attacker_ip = line.split(' ')[0]
                    break
        except Exception:
            pass

        try:
            # Transmit the file and the detected IP to the AI master server for analysis.
            with open(filepath, 'rb') as f:
                res = requests.post(
                    self.server_url,
                    files={'file': f},
                    data={'original_ip': attacker_ip},
                    timeout=5
                )

            # Process the AI server's classification decision.
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "MALICIOUS":
                    self._handle_malicious(filepath)
                else:
                    self._handle_benign(filepath)
        except Exception as e:
            print(f"[ERROR] Analysis failed for {filepath.name}: {e}")

    def _handle_benign(self, filepath: Path):
        # Relocate verified safe files to the public-facing web directory.
        dest = self.www_dir / filepath.name
        shutil.move(str(filepath), str(dest))
        print(f"[OK] {filepath.name} is clean. Moved to web directory.")

    def _handle_malicious(self, filepath: Path):
        dest = self.quarantine_dir / filepath.name

        # Isolate the threat and revoke all execution permissions immediately.
        shutil.move(str(filepath), str(dest))
        os.chmod(dest, 0o000)
        print(f"[ALERT] {filepath.name} is MALICIOUS! Quarantined.")

        # Initiate the trace-and-ban protocol for the offending IP.
        self._hunt_and_ban(filepath.name)

    def _hunt_and_ban(self, filename: str):
        # Trace the specific malicious file back to its source IP in the logs.
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()

            for line in reversed(lines):
                if f'"{filename}"' in line:
                    attacker_ip = line.split(' ')[0]
                    self._ban_ip(attacker_ip)
                    return
        except Exception as e:
            print(f"[WARN] Log parsing failed: {e}")

    def _ban_ip(self, ip: str):
        # Persist the attacker's IP to the application's internal ban list.
        with open(self.ban_file, "a+") as f:
            f.seek(0)
            if ip not in f.read():
                f.write(f"{ip}\n")
                print(f"[FIREWALL] IP {ip} added to ban list.")

        # Apply a system-level iptables DROP rule if executing with root privileges.
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)


if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = BASE_DIR.parent
    load_dotenv(PROJECT_ROOT / ".env")

    SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
    SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
    
    # Initialize the security agent with necessary paths and endpoints.
    agent = SecurityAgent(
        server_url=f"http://{SERVER_HOST}:{SERVER_PORT}/analyze",
        staging_dir=BASE_DIR / "staging",
        www_dir=BASE_DIR / "test_www",
        quarantine_dir=BASE_DIR / "quarantine",
        log_file=BASE_DIR / "access.log",
        ban_file=BASE_DIR / "banned_ips.txt"
    )

    # Configure and launch the Watchdog observer to monitor the staging area.
    observer = Observer()
    observer.schedule(agent, str(agent.staging_dir), recursive=False)
    observer.start()

    print("\n" + "=" * 50)
    print(" 🛡️  SECURITY AGENT IS ACTIVE")
    print("=" * 50)
    print(f" [+] Watching   : {agent.staging_dir.name}/")
    print(f" [+] Reporting  : {agent.server_url}")
    print(f" [+] Quarantine : {agent.quarantine_dir.name}/")
    print(" [i] Press CTRL+C to exit.")
    print("=" * 50 + "\n")

    # Keep the main thread alive while the observer runs in the background.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    # Ensure a clean shutdown of the observer thread.
    observer.join()