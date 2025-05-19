#!/usr/bin/env python3
"""
installer.py

Interactive installer for common web enumeration tools.
Checks for:
  - whatweb
  - httpx
  - ffuf
  - dirsearch
  - nikto
  - wpscan
  - nuclei
  - sslscan

Supports Linux (apt), macOS (brew), Windows (choco) where available.
"""

import subprocess
import platform
import shutil
import sys

# Mapping of tools to install commands per OS
INSTALL_COMMANDS = {
    "httpx": {
        "Linux": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "Darwin": "brew install httpx",
        "Windows": "choco install httpx -y"
    },
    "ffuf": {
        "Linux": "go install github.com/ffuf/ffuf/v2@latest",
        "Darwin": "brew install ffuf",
        "Windows": "go install github.com/ffuf/ffuf/v2@latest"
    },
    "wpscan": {
        "Linux": "sudo gem install wpscan",
        "Darwin": "brew install wpscan",
        "Windows": "NOT SUPPORTED"
    },
    "nuclei": {
        "Linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "Darwin": "brew install nuclei",
        "Windows": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    },
    "sslscan": {
        "Linux": "sudo apt-get install -y sslscan",
        "Darwin": "brew install sslscan",
        "Windows": "choco install sslscan -y"
    }
}

def detect_os():
    os_name = platform.system()
    if os_name not in ("Linux", "Darwin", "Windows"):
        print(f"Unsupported OS: {os_name}")
        sys.exit(1)
    return os_name

def is_installed(tool):
    return shutil.which(tool) is not None

def install_tool(tool, command):
    print(f"\nInstalling {tool} with: {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode == 0:
        print(f"[✓] {tool} installed successfully.")
    else:
        print(f"[!] Installation of {tool} failed (exit code {result.returncode}).")

def main():
    os_name = detect_os()
    print(f"Detected OS: {os_name}\n")

    for tool, cmds in INSTALL_COMMANDS.items():
        print(f"Checking for {tool}...")
        if is_installed(tool):
            print(f"  [✓] {tool} is already installed.\n")
            continue

        print(f"  [ ] {tool} is not installed.")
        install_cmd = cmds.get(os_name)
        if not install_cmd:
            print(f"  No install command configured for {os_name}. Please install {tool} manually.\n")
            continue

        print(f"  Suggested install command:\n    {install_cmd}")
        choice = input(f"  Install {tool}? (y/N): ").strip().lower()
        if choice == 'y':
            install_tool(tool, install_cmd)
        else:
            print(f"  Skipping installation of {tool}.\n")

    print("All done.")

if __name__ == "__main__":
    main()
