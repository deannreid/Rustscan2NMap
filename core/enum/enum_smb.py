import os
import subprocess

from core.utils import fncPrintMessage
from core.handlers import fncEnsureInstalled


def fncRunSMBEnum(target: str, save_location: str):
    _run_netexec(target, save_location)
    _run_enum4linux(target, save_location)


def _run_netexec(target: str, save_location: str):
    if not fncEnsureInstalled("netexec", "pip install netexec"):
        return
    fncPrintMessage("Running netexec SMB…", "info")
    output_file = os.path.join(save_location, f"{target}_netexec_smb.txt")
    try:
        proc = subprocess.Popen(
            ["netexec", "smb", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=120)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        if err:
            fncPrintMessage(f"netexec stderr: {err.decode('utf-8', errors='replace')}", "warning")
        fncPrintMessage(f"netexec results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("netexec timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"netexec error: {e}", "error")


def _run_enum4linux(target: str, save_location: str):
    if not fncEnsureInstalled("enum4linux-ng", "pip install enum4linux-ng"):
        return
    fncPrintMessage("Running enum4linux-ng…", "info")
    output_file = os.path.join(save_location, f"{target}_enum4linux_ng.txt")
    try:
        proc = subprocess.Popen(
            ["enum4linux-ng", "-A", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(timeout=300)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(out.decode("utf-8", errors="replace"))
        if err:
            fncPrintMessage(f"enum4linux-ng stderr: {err.decode('utf-8', errors='replace')}", "warning")
        fncPrintMessage(f"enum4linux-ng results → {output_file}", "success")
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("enum4linux-ng timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"enum4linux-ng error: {e}", "error")
