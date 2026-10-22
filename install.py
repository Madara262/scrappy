import subprocess
import sys
import os

def main():
    print("[*] Setting up Python Security Scanner environment...")

    # 1. Create virtual environment
    venv_dir = ".venv"
    if not os.path.exists(venv_dir):
        print("[*] Creating virtual environment (.venv)...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    else:
        print("[*] Virtual environment already exists.")

    # 2. Determine pip path inside venv
    if sys.platform == "win32":
        pip_path = os.path.join(venv_dir, "Scripts", "pip")
        activate_cmd = f"{venv_dir}\\Scripts\\activate"
    else:
        pip_path = os.path.join(venv_dir, "bin", "pip")
        activate_cmd = f"source {venv_dir}/bin/activate"

    # 3. Upgrade pip and install requirements
    print("[*] Installing dependencies from requirements.txt...")
    subprocess.check_call([pip_path, "install", "--upgrade", "pip"])
    if os.path.exists("requirements.txt"):
        subprocess.check_call([pip_path, "install", "-r", "requirements.txt"])
    else:
        print("[!] Warning: requirements.txt not found. Skipping dependency installation.")

    print("\n[+] Setup complete successfully!")
    print(f"\nTo activate your environment, run:\n  {activate_cmd}")
    print("\nTo run the scanner:\n  python scanner.py")

if __name__ == "__main__":
    main()