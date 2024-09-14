#!/usr/bin/env python3

import subprocess
import sys
import os
import platform
import json
import random
from colorama import Fore, Style, init
import ctypes
import argparse
import re
import requests

init(autoreset=True)

CONFIG_FILE = os.path.expanduser("~/.rs2nm/config.json")
DOWNLOAD_URL = "http://example.com/path/to/your/latest/rs2nm.py"  # Replace with actual URL
TARGET_DIR = "/usr/bin"
TARGET_FILE = "rs2nm.py"
ALIAS_NAME = "rs2nm"
ALIAS_COMMAND = f"python3 {os.path.join(TARGET_DIR, TARGET_FILE)}"

def checkConfigDir():
    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

def is_admin():
    if platform.system().lower() == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            print_message("Could not determine admin privileges on Windows: " + str(e), "error")
            sys.exit(1)
    elif platform.system().lower() in ["linux", "darwin"]:
        return os.geteuid() == 0
    else:
        return False

def check_python_version():
    python_version = sys.version.split()[0]
    print_message(f"Python Version Detected: {python_version}", "info")
    if sys.version_info < (3, 10):
        print_message("This script requires Python 3.10.0 or higher. Please upgrade your Python version.", "error")
        sys.exit(1)

def run_command(command, cwd=None):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    output, error = process.communicate()
    return output.decode().strip(), error.decode().strip()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    return {
        "dependencies": {},
        "disabled_features": [],
        "enable_bloodhound": True,
        "enable_ldap_utils": True,
        "enable_enum4linux_ng": True,
        "enable_netexec": True,
        "output_directory": os.path.expanduser("~/rs2nm_output")
    }

def save_config(config):
    checkConfigDir()
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

def install_dependency(tool, config):
    install_commands = {
        "Rustscan": {
            "linux": install_rustscan,
            "windows": None,  # Not applicable
            "darwin": None  # Not applicable
        },
        "Netexec": {
            "linux": ["sudo", "apt-get", "install", "-y", "netexec"],
            "windows": None,  # Not applicable
            "darwin": None  # Not applicable
        },
        "Nmap": {
            "linux": ["sudo", "apt-get", "install", "-y", "nmap"],
            "windows": ["winget", "install", "-e", "--id", "Insecure.Nmap"],
            "darwin": ["brew", "install", "nmap"]
        },
        "enum4linux-ng": {
            "linux": ["sudo", "apt-get", "install", "-y", "enum4linux-ng"],
            "windows": None,  # Not applicable
            "darwin": None  # Not applicable
        },
        "ldap-utils": {
            "linux": ["sudo", "apt-get", "install", "-y", "ldap-utils"],
            "windows": [sys.executable, "-m", "pip", "install", "ldap3"],
            "darwin": ["brew", "install", "ldap-utils"]
        },
        "BloodHound": {
            "linux": install_bloodhound,
            "windows": None,  # Not applicable
            "darwin": None  # Not applicable
        },
        "Python dependencies": {
            "linux": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "windows": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "darwin": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        }
    }

    system = platform.system().lower()
    if tool in install_commands and install_commands[tool][system]:
        print_message(f"Installing {tool}...", "info")
        command = install_commands[tool][system]
        if callable(command):
            command()
        else:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for line in process.stdout:
                print(Fore.GREEN + line.decode().strip() + Style.RESET_ALL)
            process.wait()
            if process.returncode != 0:
                print_message(f"Error installing {tool}", "error")
                sys.exit(1)
        print_message(f"{tool} installed successfully.", "success")

def install_rustscan():
    print_message("Installing Rustscan...", "info")
    release_url = get_latest_rustscan_release()
    if not release_url:
        print_message("Could not find the latest Rustscan release.", "error")
        sys.exit(1)

    deb_file = release_url.split('/')[-1]
    command = ["wget", "-O", deb_file, release_url]
    output, error = run_command(command)
    if error:
        print_message(f"Error downloading Rustscan: {error}", "error")
        sys.exit(1)

    command = ["sudo", "dpkg", "-i", deb_file]
    output, error = run_command(command)
    if error:
        print_message(f"Error installing Rustscan: {error}", "error")
        sys.exit(1)

    print_message("Rustscan installed successfully.", "success")

def get_latest_rustscan_release():
    print_message("Fetching the latest Rustscan release...", "info")
    releases_url = "https://github.com/RustScan/RustScan/releases"
    response = requests.get(releases_url)
    if response.status_code != 200:
        return None

    match = re.search(r'/RustScan/RustScan/releases/download/(\d+\.\d+\.\d+)/rustscan_\d+\.\d+\.\d+_amd64\.deb', response.text)
    if match:
        return f"https://github.com{match.group(0)}"
    return None

def install_bloodhound():
    print_message("Installing BloodHound...", "info")
    command = ["curl", "-L", "https://ghst.ly/getbhce", "|", "docker", "compose", "-f", "-", "up"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    for line in process.stdout:
        print(Fore.GREEN + line.decode().strip() + Style.RESET_ALL)
    process.wait()
    if process.returncode != 0:
        print_message("Error installing BloodHound", "error")
        sys.exit(1)
    print_message("BloodHound installed successfully.", "success")

def check_dependencies(config):
    print_message("Checking Dependencies", "info")

    dependencies = {
        "Rustscan": "rustscan",
        "Netexec": "netexec",
        "Nmap": "nmap",
        "enum4linux-ng": "enum4linux-ng",
        "ldap-utils": "ldapsearch",
        "BloodHound": "bloodhound",
        "Python dependencies": "pip"
    }

    if not config.get("enable_bloodhound", True):
        config["disabled_features"].append("BloodHound")
    if not config.get("enable_ldap_utils", True):
        config["disabled_features"].append("ldap-utils")
    if not config.get("enable_enum4linux_ng", True):
        config["disabled_features"].append("enum4linux-ng")
    if not config.get("enable_netexec", True):
        config["disabled_features"].append("Netexec")

    system = platform.system().lower()
    which_command = "which" if system != "windows" else "where"

    for tool, command in dependencies.items():
        if tool in config["disabled_features"]:
            print_message(f"Skipping disabled feature: {tool}", "disabled")
            continue

        command_check = f"{which_command} {command}" if command != "pip" else "pip --version"
        output, error = run_command(command_check.split())

        if "not found" in output or error or "is not recognized" in error:
            print_message(f"{tool} is not installed.", "error")
            while True:
                choice = input(Fore.YELLOW + f"Do you want to install {tool}? (y/n): " + Style.RESET_ALL)
                if choice.lower() == 'y':
                    install_dependency(tool, config)
                    config["dependencies"][tool] = "installed"
                    break
                elif choice.lower() == 'n':
                    config["dependencies"][tool] = "skipped"
                    save_config(config)
                    print_message(f"Skipping installation of {tool}. This may affect script functionality.", "warning")
                    break
                else:
                    print_message("Invalid input. Please enter 'y' or 'n'.", "error")
        else:
            print_message(f"{tool} is already installed.", "success")
            config["dependencies"][tool] = "installed"

    save_config(config)

def download_and_install_rs2nm():
    print_message("Downloading the latest version of rs2nm.py...", "
