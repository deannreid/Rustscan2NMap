import subprocess
import os
import json
from core.utils import fncPrintMessage

def fncRunRustscan(target):
    fncPrintMessage(f"Target: {target}", "success")
    fncPrintMessage("Checking for existing scan results...", "info")

    temp_dir = os.path.join(os.path.expanduser("~/.rs2nm"), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    scan_file = os.path.join(temp_dir, f"rs2nm_{target}.json")

    if os.path.exists(scan_file):
        fncPrintMessage("Previous scan data found. Running a quick compare...", "info")

        quick_command = ["rustscan", "-g", "-a", target, "--ulimit", "70000"]
        quick_proc = subprocess.Popen(quick_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        quick_output, _ = quick_proc.communicate()

        new_ports = ""
        for line in quick_output.decode().split('\n'):
            if "->" in line:
                new_ports = line.split("->")[1].strip()[1:-1]
                break

        try:
            with open(scan_file, "r") as f:
                old_data = json.load(f)
                old_ports = old_data.get("ports", "")

            if set(new_ports.split(",")) != set(old_ports.split(",")):
                fncPrintMessage("Port set has changed:", "warning")
                fncPrintMessage(f"Old: {old_ports}", "info")
                fncPrintMessage(f"New: {new_ports}", "info")
                response = input("Replace old scan with new ports? (y/n): ").strip().lower()
                if response != "y":
                    fncPrintMessage("Keeping previous scan data.", "info")
                    fncPrintMessage(f"Using cached scan data from: {scan_file}", "info")
                    return old_ports
                else:
                    with open(scan_file, "w") as f:
                        json.dump({"ip": target, "ports": new_ports}, f)
                    fncPrintMessage("Updated stored scan data.", "success")
                    fncPrintMessage(f"Scan file updated: {scan_file}", "info")
                    return new_ports
            else:
                fncPrintMessage("No changes in open ports since last scan.", "info")
                return old_ports
        except Exception as e:
            fncPrintMessage(f"Error reading previous scan data: {e}", "error")

    fncPrintMessage("Running full Rustscan", "info")
    fncPrintMessage("Estimated Time Remaining: 1h 35m\nJust kidding, only going to take a few seconds, they say\n", "info")

    rustscan_command = ["rustscan", "-g", "-a", target, "--ulimit", "70000"]
    process = subprocess.Popen(rustscan_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        fncPrintMessage("Rustscan error:\n" + error.decode(), "error")
        return ""

    for line in output.decode().split('\n'):
        if "->" in line:
            ports = line.split("->")[1].strip()[1:-1]
            fncPrintMessage(f"Ports discovered: {ports}", "success")
            with open(scan_file, "w") as f:
                json.dump({"ip": target, "ports": ports, "nmap_complete": False}, f)
            fncPrintMessage(f"Scan file created: {scan_file}", "info")
            return ports

    fncPrintMessage("No open ports found by Rustscan.", "info")
    return ""

def fncRunNmap(target: str, ports: str, output_file: str):
    """
    Run Nmap against <target> on <ports>, save with -oA <output_file>,
    and retry with -Pn if host seems down.
    Returns (stdout, stderr) decoded as strings.
    """
    fncPrintMessage("Running Nmap", "info")
    fncPrintMessage(
        "This can take a few moments depending on how many ports are available",
        "info"
    )

    command = ["nmap", "-p", ports, "-sC", "-sV", "-oA", output_file, target]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    decoded = out.decode()

    if "Note: Host seems down." in decoded:
        fncPrintMessage("Host seems down. Retrying with -Pn", "warning")
        command.insert(1, "-Pn")
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

    return out.decode(), err.decode()

def fncDetectOSFromNmap(nmap_output: str) -> str:
    """
    Look for common OS strings in Nmap output to return 'windows', 'linux', 'unix', or 'unknown'.
    """
    if "Windows" in nmap_output:
        return "windows"
    if "Linux" in nmap_output:
        return "linux"
    if "Unix" in nmap_output or "BSD" in nmap_output:
        return "unix"
    return "unknown"