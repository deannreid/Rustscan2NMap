import os
import subprocess

from core.utils import fncPrintMessage
from core.handlers import fncEnsureInstalled


def fncRunLDAPEnum(target: str, save_location: str, username: str = None, password: str = None):
    _run_ldapsearch(target, save_location)
    if username and password:
        domain = input("Enter domain for BloodHound (or press Enter to skip): ").strip()
        if domain:
            _run_bloodhound(target, save_location, domain=domain, username=username, password=password)
    else:
        fncPrintMessage("No credentials provided; skipping BloodHound.", "info")


def _run_ldapsearch(target: str, save_location: str):
    if not fncEnsureInstalled("ldapsearch", "apt install ldap-utils"):
        return
    fncPrintMessage("Running ldapsearch (anonymous)…", "info")
    output_file = os.path.join(save_location, f"{target}_ldapsearch.txt")
    try:
        proc = subprocess.Popen(
            ["ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "sub", "(objectClass=*)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=60)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        if err:
            fncPrintMessage(f"ldapsearch stderr: {err.decode('utf-8', errors='replace')}", "warning")
        fncPrintMessage(f"ldapsearch results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("ldapsearch timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"ldapsearch error: {e}", "error")


def _run_bloodhound(target: str, save_location: str, domain: str, username: str, password: str):
    if not fncEnsureInstalled("bloodhound-python", "pip install bloodhound"):
        return
    fncPrintMessage("Running bloodhound-python…", "info")
    output_file = os.path.join(save_location, f"{target}_bloodhound.txt")
    try:
        proc = subprocess.Popen(
            ["bloodhound-python", "-d", domain, "-u", username, "-p", password,
             "-gc", target, "-c", "All"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=300)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        if err:
            fncPrintMessage(f"bloodhound-python stderr: {err.decode('utf-8', errors='replace')}", "warning")
        fncPrintMessage(f"BloodHound results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("bloodhound-python timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"bloodhound-python error: {e}", "error")
