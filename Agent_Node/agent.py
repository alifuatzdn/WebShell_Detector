import os
import shutil
import subprocess
import time
import requests
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class SecurityAgent(FileSystemEventHandler):
    """
    This agent watches the staging folder. Whenever a new file is added,
    it sends it to the Master Server for AI analysis. Based on the result,
    it either publishes the file or quarantines it and bans the attacker.
    """

    def __init__(self, server_url, staging_dir, www_dir, quarantine_dir, log_file, ban_file):
        self.server_url = server_url
        self.staging_dir = Path(staging_dir)
        self.www_dir = Path(www_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.log_file = Path(log_file)
        self.ban_file = Path(ban_file)

    def on_created(self, event):
        """Triggered automatically by Watchdog when a new file is created."""
        # Only process PHP and TXT files, ignore directories
        if not event.is_directory and event.src_path.endswith(('.php', '.txt')):
            self.process_file(Path(event.src_path))

    def process_file(self, filepath: Path):
        """Sends the newly detected file to the central server for AI analysis."""
        # Wait slightly to ensure the OS has finished writing the file to disk
        time.sleep(0.5)

        # Before sending to the master, let's look up the REAL attacker's IP from the access log
        attacker_ip = "127.0.0.1"  # default fallback
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
            # Open the file and POST it to the server
            with open(filepath, 'rb') as f:
                res = requests.post(
                    self.server_url,
                    files={'file': f},
                    data={'original_ip': attacker_ip},  # Send the real IP we detected
                    timeout=5
                )

            # Check the server's response
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "MALICIOUS":
                    self._handle_malicious(filepath)
                else:
                    self._handle_benign(filepath)
        except Exception as e:
            print(f"[ERROR] Analysis failed for {filepath.name}: {e}")

    def _handle_benign(self, filepath: Path):
        """If the file is clean, move it to the public web folder (test_www)."""
        dest = self.www_dir / filepath.name
        shutil.move(str(filepath), str(dest))
        print(f"[OK] {filepath.name} is clean. Moved to web directory.")

    def _handle_malicious(self, filepath: Path):
        """If the file is malicious, quarantine it and start the banning process."""
        dest = self.quarantine_dir / filepath.name

        # Move the file out of staging and strip its execution permissions
        shutil.move(str(filepath), str(dest))
        os.chmod(dest, 0o000)
        print(f"[ALERT] {filepath.name} is MALICIOUS! Quarantined.")

        # Find who uploaded it
        self._hunt_and_ban(filepath.name)

    def _hunt_and_ban(self, filename: str):
        """Reads the access logs to find the IP address that uploaded the malicious file."""
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()

            # Read from bottom to top to find the most recent matching log entry
            for line in reversed(lines):
                if f'"{filename}"' in line:
                    attacker_ip = line.split(' ')[0]
                    self._ban_ip(attacker_ip)
                    return
        except Exception as e:
            print(f"[WARN] Log parsing failed: {e}")

    def _ban_ip(self, ip: str):
        """Adds the attacker's IP to the ban list and applies firewall rules if possible."""
        # Step 1: Add to our Python application's ban list
        with open(self.ban_file, "a+") as f:
            f.seek(0)
            if ip not in f.read():
                f.write(f"{ip}\n")
                print(f"[FIREWALL] IP {ip} added to ban list.")

        # Step 2: Apply OS-level Iptables firewall rules (if running on a Linux root account)
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)


if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent

    agent = SecurityAgent(
        server_url="http://127.0.0.1:5000/analyze",
        staging_dir=BASE_DIR / "staging",
        www_dir=BASE_DIR / "test_www",
        quarantine_dir=BASE_DIR / "quarantine",
        log_file=BASE_DIR / "access.log",
        ban_file=BASE_DIR / "banned_ips.txt"
    )

    observer = Observer()
    observer.schedule(agent, str(agent.staging_dir), recursive=False)
    observer.start()

    # Beautiful terminal output for the Agent
    print("\n" + "=" * 50)
    print(" 🛡️  SECURITY AGENT IS ACTIVE")
    print("=" * 50)
    print(f" [+] Watching   : {agent.staging_dir.name}/")
    print(f" [+] Reporting  : {agent.server_url}")
    print(f" [+] Quarantine : {agent.quarantine_dir.name}/")
    print(" [i] Press CTRL+C to exit.")
    print("=" * 50 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()