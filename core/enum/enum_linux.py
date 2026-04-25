import os
import subprocess

from core.utils import fncPrintMessage
from core.handlers import fncEnsureInstalled


def fncRunLinuxEnum(target: str, save_location: str, username: str = None, password: str = None):
    fncPrintMessage("Starting Linux enumeration…", "info")
    _enum_rpc(target, save_location)
    _enum_nfs(target, save_location)
    _enum_ssh_nmap(target, save_location)
    if username:
        fncPrintMessage(f"Credentials provided; using '{username}' for SSH checks.", "info")
    else:
        if input("Brute-force SSH with Hydra? (y/n): ").strip().lower() == "y":
            _bruteforce_ssh(target, save_location)


def _enum_rpc(target: str, save_location: str):
    if not fncEnsureInstalled("rpcinfo", "apt install rpcbind"):
        return
    fncPrintMessage("Querying RPC services…", "info")
    output_file = os.path.join(save_location, f"{target}_rpcinfo.txt")
    try:
        proc = subprocess.Popen(
            ["rpcinfo", "-p", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=30)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        fncPrintMessage(f"rpcinfo results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("rpcinfo timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"rpcinfo error: {e}", "error")


def _enum_nfs(target: str, save_location: str):
    if not fncEnsureInstalled("showmount", "apt install nfs-common"):
        return
    fncPrintMessage("Checking NFS exports…", "info")
    output_file = os.path.join(save_location, f"{target}_nfs.txt")
    try:
        proc = subprocess.Popen(
            ["showmount", "-e", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=30)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        fncPrintMessage(f"NFS exports → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("showmount timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"showmount error: {e}", "error")


def _enum_ssh_nmap(target: str, save_location: str):
    if not fncEnsureInstalled("nmap", "apt install nmap"):
        return
    fncPrintMessage("Running nmap SSH enumeration scripts…", "info")
    output_base = os.path.join(save_location, f"{target}_ssh_nmap")
    scripts = "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos"
    try:
        proc = subprocess.Popen(
            ["nmap", "-p", "22", "--script", scripts, "-oA", output_base, target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=120)
        fncPrintMessage(f"SSH nmap results → {output_base}", "success")
        print(out.decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("nmap SSH scan timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"nmap SSH error: {e}", "error")


def _bruteforce_ssh(target: str, save_location: str):
    if not fncEnsureInstalled("hydra", "apt install hydra"):
        return
    fncPrintMessage("Preparing Hydra SSH brute-force…", "info")
    wordlist = input("Path to combo wordlist (user:pass per line, or press Enter to skip): ").strip()
    if not wordlist or not os.path.isfile(wordlist):
        fncPrintMessage("No valid wordlist; skipping Hydra.", "warning")
        return
    output_file = os.path.join(save_location, f"{target}_hydra_ssh.txt")
    try:
        proc = subprocess.Popen(
            ["hydra", "-C", wordlist, f"ssh://{target}", "-o", output_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=600)
        fncPrintMessage(f"Hydra SSH results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("Hydra timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"Hydra error: {e}", "error")
