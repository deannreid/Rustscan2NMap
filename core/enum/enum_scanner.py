import re
import shutil
import subprocess

from core.utils import fncPrintMessage, ask
from core.handlers import fncLoadScanState, fncSaveScanState

_PORT_RE = re.compile(r'\[([^\]]+)\]')

RUSTSCAN_TIMEOUT = 300   # seconds
NMAP_TIMEOUT     = 900   # 15 minutes — large port sets can take a while


def _check_tool(name: str, hint: str = "") -> bool:
    if shutil.which(name) is None:
        msg = f"'{name}' not found in PATH."
        if hint:
            msg += f" ({hint})"
        fncPrintMessage(msg, "error")
        return False
    return True


def _parse_ports(output: str) -> str:
    for line in output.splitlines():
        if "->" in line:
            m = _PORT_RE.search(line)
            if m:
                return m.group(1)
    return ""


def fncRunRustscan(target: str) -> str:
    if not _check_tool("rustscan", "https://github.com/RustScan/RustScan"):
        return ""

    fncPrintMessage(f"Target: {target}", "success")
    fncPrintMessage("Checking for existing scan results…", "info")

    scan_file, state = fncLoadScanState(target)
    old_ports = state.get("ports", "")

    if old_ports:
        fncPrintMessage("Previous scan data found. Running quick compare…", "info")
        try:
            quick = subprocess.Popen(
                ["rustscan", "-g", "-a", target, "--ulimit", "70000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = quick.communicate(timeout=RUSTSCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            quick.kill()
            fncPrintMessage("Quick scan timed out; using cached ports.", "warning")
            return old_ports
        except Exception as e:
            fncPrintMessage(f"Rustscan error: {e}", "error")
            return old_ports

        new_ports = _parse_ports(out.decode("utf-8", errors="replace"))
        if not new_ports:
            fncPrintMessage("Quick scan returned no ports; falling back to cached.", "warning")
            return old_ports

        if set(new_ports.split(",")) != set(old_ports.split(",")):
            fncPrintMessage("Port set has changed:", "warning")
            fncPrintMessage(f"Old: {old_ports}", "info")
            fncPrintMessage(f"New: {new_ports}", "info")
            if ask("Replace old scan with new ports? (y/n): ", default="y") == "y":
                state.update({"ip": target, "ports": new_ports, "nmap_complete": False})
                fncSaveScanState(scan_file, state)
                fncPrintMessage("Updated stored scan data.", "success")
                return new_ports
            fncPrintMessage("Keeping previous scan data.", "info")
            return old_ports

        return old_ports

    fncPrintMessage("Running full Rustscan…", "info")
    try:
        rs = subprocess.Popen(
            ["rustscan", "-g", "-a", target, "--ulimit", "70000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = rs.communicate(timeout=RUSTSCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        rs.kill()
        fncPrintMessage("Rustscan timed out.", "error")
        return ""
    except Exception as e:
        fncPrintMessage(f"Rustscan error: {e}", "error")
        return ""

    if err:
        fncPrintMessage("Rustscan stderr:\n" + err.decode("utf-8", errors="replace"), "error")

    ports = _parse_ports(out.decode("utf-8", errors="replace"))
    if not ports:
        fncPrintMessage("No open ports found by Rustscan.", "info")
        return ""

    fncPrintMessage(f"Ports discovered: {ports}", "success")
    state.update({"ip": target, "ports": ports, "nmap_complete": False})
    fncSaveScanState(scan_file, state)
    fncPrintMessage(f"Scan file created: {scan_file}", "info")
    return ports


def fncRunNmap(target: str, ports: str, output_file: str):
    if not _check_tool("nmap", "https://nmap.org/download"):
        return "", "nmap not found"

    fncPrintMessage("Running Nmap (this may take a few minutes)…", "info")
    command = ["nmap", "-p", ports, "-sC", "-sV", "-oA", output_file, target]

    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("Nmap timed out.", "error")
        return "", "timeout"
    except Exception as e:
        fncPrintMessage(f"Nmap error: {e}", "error")
        return "", str(e)

    decoded = out.decode("utf-8", errors="replace")

    if "Note: Host seems down." in decoded:
        fncPrintMessage("Host seems down. Retrying with -Pn…", "warning")
        command.insert(1, "-Pn")
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=NMAP_TIMEOUT)
            decoded = out.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            fncPrintMessage("Nmap -Pn retry timed out.", "error")
            return decoded, "timeout"

    return decoded, err.decode("utf-8", errors="replace")


def fncDetectOSFromNmap(nmap_output: str) -> str:
    if "Windows" in nmap_output:
        return "windows"
    if "Linux" in nmap_output:
        return "linux"
    if "Unix" in nmap_output or "BSD" in nmap_output:
        return "unix"
    return "unknown"
