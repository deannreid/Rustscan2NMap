import subprocess
import os
import json
from core.utils import fncPrintMessage
from core.handlers import fncLoadScanState, fncSaveScanState

def fncRunRustscan(target: str) -> str:
    fncPrintMessage(f"Target: {target}", "success")
    fncPrintMessage("Checking for existing scan results...", "info")

    scan_file, state = fncLoadScanState(target)
    old_ports = state.get("ports", "")
    # quick‐compare
    if old_ports:
        fncPrintMessage("Previous scan data found. Running a quick compare...", "info")
        quick = subprocess.Popen(
            ["rustscan","-g","-a",target,"--ulimit","70000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = quick.communicate()
        new_ports = next(
            (l.split("->",1)[1].strip()[1:-1]
             for l in out.decode().splitlines() if "->" in l),
            ""
        )
        if not new_ports:
            fncPrintMessage("Quick scan failed; falling back to full scan.", "warning")
        elif set(new_ports.split(",")) != set(old_ports.split(",")):
            fncPrintMessage("Port set has changed:", "warning")
            fncPrintMessage(f"Old: {old_ports}", "info")
            fncPrintMessage(f"New: {new_ports}", "info")
            if input("Replace old scan with new ports? (y/n): ").strip().lower() == "y":
                state.update({"ip": target, "ports": new_ports, "nmap_complete": False})
                fncSaveScanState(scan_file, state)
                fncPrintMessage("Updated stored scan data.", "success")
                return new_ports
            fncPrintMessage("Keeping previous scan data.", "info")
            return old_ports
        else:
            return old_ports

    # full scan
    fncPrintMessage("Running full Rustscan", "info")
    rs = subprocess.Popen(
        ["rustscan","-g","-a",target,"--ulimit","70000"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = rs.communicate()
    if err:
        fncPrintMessage("Rustscan error:\n"+err.decode(), "error")
        return ""
    ports = next(
        (l.split("->",1)[1].strip()[1:-1]
         for l in out.decode().splitlines() if "->" in l),
        ""
    )
    if not ports:
        fncPrintMessage("No open ports found by Rustscan.", "info")
        return ""
    fncPrintMessage(f"Ports discovered: {ports}", "success")
    state.update({"ip": target, "ports": ports, "nmap_complete": False})
    fncSaveScanState(scan_file, state)
    fncPrintMessage(f"Scan file created: {scan_file}", "info")
    return ports

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