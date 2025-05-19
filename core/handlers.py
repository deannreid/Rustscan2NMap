import os
import json
import re
import shutil
from .utils import fncPrintMessage
from config import CONFIG_PATH, HOSTS_FILE, LDAP_PORTS

def fncEnsureInstalled(tool_name, install_hint=None):
    """
    Check if `tool_name` is on PATH; if missing, warn and allow user to skip.
    Returns True if the tool is available, False to skip its scan.
    """
    if shutil.which(tool_name) is None:
        msg = f"'{tool_name}' is not installed or not in PATH."
        if install_hint:
            msg += f" (Hint: {install_hint})"
        fncPrintMessage(msg, "warning")
        choice = input(f" Skip {tool_name} scan? (y/n): ").strip().lower()
        if choice == 'y':
            fncPrintMessage(f"Skipping {tool_name}.", "info")
            return False
        else:
            fncPrintMessage(f"Please install {tool_name} and re-run when ready.", "warning")
            return False
    return True

def fncCheckConfigFileExists():
    if os.path.exists(CONFIG_PATH):
        fncPrintMessage(f"Configuration file found: {CONFIG_PATH}", "info")
    else:
        fncPrintMessage(f"Configuration file not found: {CONFIG_PATH}", "warning")

def fncLoadSkippedDependencies():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as file:
            return json.load(file)
    return []

def fncSaveSkippedDependencies(skipped_dependencies):
    with open(CONFIG_PATH, "w") as file:
        json.dump(skipped_dependencies, file)

def fncAddToHosts(target_ip, domain):
    try:
        with open(HOSTS_FILE, 'a') as hosts_file:
            hosts_file.write(f"{target_ip}\t{domain}\n")
        fncPrintMessage(f"Added {domain} to hosts file with IP {target_ip}", "success")
        fncPrintMessage("!!! Reminder: Remember to remove the IP/Host after your engagement !!","info")
    except PermissionError:
        fncPrintMessage("Permission denied: Unable to write to the hosts file.", "error")
    except Exception as e:
        fncPrintMessage(f"Error writing to hosts file: {e}", "error")

def fncGetDomainsFromNmap(nmap_output):
    fncPrintMessage("Checking for domain information", "info")
    domains = set()

    for line in nmap_output.split('\n'):
        if any(port + "/tcp" in line for port in LDAP_PORTS) and 'open' in line and 'LDAP' in line:
            match = re.search(r'Domain: ([^\s,]+)', line)
            if match:
                domains.add(match.group(1).rstrip('.0'))

        if 'Subject Alternative Name' in line and 'DNS:' in line:
            domains.update(re.findall(r'DNS:([^,]+)', line))

        if 'Nmap scan report for' in line:
            match = re.search(r'Nmap scan report for ([^\s]+)', line)
            if match:
                domains.add(match.group(1))

        if '|_http-title: Did not follow redirect to http://' in line:
            match = re.search(r'http:\/\/([^\/]+)', line)
            if match:
                domains.add(match.group(1))

        if '|_https-title: Did not follow redirect to https://' in line:
            match = re.search(r'https:\/\/([^\/]+)', line)
            if match:
                domains.add(match.group(1))

    return list(domains)



def fncSmbPortsOpen(open_ports):
    from config import SMB_PORTS
    return any(port in SMB_PORTS for port in open_ports.split(','))
