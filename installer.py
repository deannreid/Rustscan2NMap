#!/usr/bin/env python3

import subprocess
import sys
import os
import platform
import json
import random
from colorama import Fore, Style, init
import ctypes

init(autoreset=True)

CONFIG_FILE = "dependency_config.json"

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

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode().strip(), error.decode().strip()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    return {
        "dependencies": {},
        "disabled_features": []
    }

def save_config(config):
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

def install_dependency(tool):
    install_commands = {
        "Rustscan": {
            "linux": ["cargo", "install", "rustscan"],
            "windows": [sys.executable, "-m", "pip", "install", "rustscan"],
            "darwin": ["cargo", "install", "rustscan"]
        },
        "Netexec": {
            "linux": [sys.executable, "-m", "pip", "install", "netexec"],
            "windows": [sys.executable, "-m", "pip", "install", "netexec"],
            "darwin": [sys.executable, "-m", "pip", "install", "netexec"]
        },
        "Nmap": {
            "linux": ["sudo", "apt-get", "install", "-y", "nmap"],
            "windows": ["choco", "install", "nmap"],
            "darwin": ["brew", "install", "nmap"]
        },
        "enum4linux-ng": {
            "linux": ["sudo", "apt-get", "install", "-y", "enum4linux-ng"],
            "windows": [sys.executable, "-m", "pip", "install", "enum4linux-ng"],
            "darwin": ["brew", "install", "enum4linux-ng"]
        },
        "ldap-utils": {
            "linux": ["sudo", "apt-get", "install", "-y", "ldap-utils"],
            "windows": [sys.executable, "-m", "pip", "install", "ldap3"],
            "darwin": ["brew", "install", "ldap-utils"]
        },
        "BloodHound": {
            "linux": ["sudo", "apt-get", "install", "-y", "bloodhound"],
            "windows": ["choco", "install", "bloodhound"],
            "darwin": ["brew", "install", "bloodhound"]
        },
        "Python dependencies": {
            "linux": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "windows": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "darwin": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        }
    }

    system = platform.system().lower()
    if tool in install_commands and system in install_commands[tool]:
        print_message(f"Installing {tool}...", "info")
        command = install_commands[tool][system]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in process.stdout:
            print(Fore.GREEN + line.decode().strip() + Style.RESET_ALL)
        process.wait()
        if process.returncode != 0:
            print_message(f"Error installing {tool}", "error")
            sys.exit(1)
        print_message(f"{tool} installed successfully.", "success")

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
                    install_dependency(tool)
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

def print_message(message, msg_type):
    symbols = {
        "info": Fore.CYAN + "{~} ",
        "warning": Fore.RED + "{!} ",
        "success": Fore.GREEN + "{✓} ",
        "error": Fore.RED + "{!} ",
        "disabled": Fore.LIGHTBLACK_EX + "{X} "
    }
    print(symbols.get(msg_type, "") + message + Style.RESET_ALL)

def print_ascii_banner():
    print(Fore.CYAN + """
_|_|_|      _|_|_|        _|_|        _|      _|  _|      _|
_|    _|  _|            _|    _|      _|_|    _|  _|_|  _|_|
_|_|_|      _|_|            _|        _|  _|  _|  _|  _|  _|
_|    _|        _|        _|          _|    _|_|  _|      _|
_|    _|  _|_|_|        _|_|_|_|      _|      _|  _|      _|

The soon to be all in one pentest enumeration tool.

------------------------------------------------
::        %INSERT RELEVANT DISCORD HERE       ::
:: https://github.com/deannreid/Rustscan2NMap ::
------------------------------------------------ """ + Style.RESET_ALL)

def print_blurb():
    blurbs = [
        "Enumerating services: Like snooping through your neighbor's Wi-Fi, but legal.\n",
        "Exploring services: The geek's way of saying 'I'm just curious!'\n",
        "Discovering endpoints: Like a treasure hunt, but with more IP addresses.\n",
        "Probing the depths: Finding the juicy bits your network's been hiding.\n"
    ]
    print(random.choice(blurbs))

if __name__ == "__main__":
    print_ascii_banner()
    print_blurb()

    check_python_version()

    if not is_admin():
        print_message("This script requires administrative privileges. Please run it as an administrator or with sudo.", "error")
        sys.exit(1)

    system = platform.system().lower()
    print_message(f"Operating System Detected: {platform.system()}", "info")
    print_message(f"Configuration file located at: {os.path.abspath(CONFIG_FILE)}", "info")

    config = load_config()
    check_dependencies(config)
    save_config(config)
