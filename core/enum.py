import os
import subprocess
from .utils import fncPrintMessage

def fncRunNetExecSMB(target_ip, save_location):
    fncPrintMessage("Running Netexec SMB", "info")
    output_file = os.path.join(save_location, f"{target_ip}_netexec_smb_results.txt")
    command = ["netexec", "smb", target_ip]

    with open(output_file, 'w') as f:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        f.write(out.decode())

    if err:
        fncPrintMessage("Netexec SMB error:\n" + err.decode(), "error")
    else:
        fncPrintMessage(f"Netexec SMB results saved: {output_file}", "success")


def fncRunEnum4LinuxNG(target_ip, save_location):
    fncPrintMessage("Running enum4linux-ng", "info")
    output_file = os.path.join(save_location, f"{target_ip}_enum4linux_ng_results.txt")
    command = ["enum4linux-ng", "-A", target_ip]

    with open(output_file, 'w') as f:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        f.write(out.decode())

    if err:
        fncPrintMessage("enum4linux-ng error:\n" + err.decode(), "error")
    else:
        fncPrintMessage(f"enum4linux-ng results saved: {output_file}", "success")


def fncRunLdapSearch(target_ip, save_location):
    fncPrintMessage("Running ldapsearch", "info")
    output_file = os.path.join(save_location, f"{target_ip}_ldapsearch_results.txt")
    command = ["ldapsearch", "-x", "-H", f"ldap://{target_ip}", "-s", "sub", "(objectClass=*)"]

    with open(output_file, 'w') as f:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        f.write(out.decode())

    if err:
        fncPrintMessage("ldapsearch error:\n" + err.decode(), "error")
    else:
        fncPrintMessage(f"ldapsearch results saved: {output_file}", "success")


def fncRunBloodhound(target_hostname, save_location, domain, username, password):
    fncPrintMessage("Running BloodHound (via bloodhound-python)", "info")
    output_file = os.path.join(save_location, f"{target_hostname}_bloodhound_results.txt")
    command = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-p", password,
        "-gc", target_hostname,
        "-c", "All"
    ]

    with open(output_file, 'w') as f:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        f.write(out.decode())

    if err:
        fncPrintMessage("BloodHound error:\n" + err.decode(), "error")
    else:
        fncPrintMessage(f"BloodHound results saved: {output_file}", "success")
