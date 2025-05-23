#!/usr/bin/env python3
import os
import sys
import signal
import urllib.request
import socket
import subprocess
import platform
import pwd

from config import DOM_LIST
from core.utils import fncPrintMessage
from core.handlers import (
    fncAddToHosts,
    fncEnsureInstalled,
    fncLaunchInNewTerminal,
    fncEnsureHostEntry
)

IS_WINDOWS = platform.system().lower() == "windows"
CREATE_NEW_CONSOLE = 0x00000010 if IS_WINDOWS else 0


def fncGetWebPort(target: str) -> str:
    """
    Check ports 80 and 443; return one to use (as string).
    If both open, prompt; if neither, ask manually.
    """
    fncPrintMessage("Checking HTTP(S) ports on target…", "info")
    open_ports = []
    for p in (80, 443):
        try:
            with socket.create_connection((target, p), timeout=1):
                open_ports.append(p)
        except Exception:
            continue

    if len(open_ports) == 1:
        return str(open_ports[0])
    if len(open_ports) == 2:
        choice = input("Both 80 and 443 are open. Which to use? [80/443]: ").strip()
        return choice if choice in ("80", "443") else "80"
    return input("Neither 80 nor 443 open—enter port to use: ").strip()


def fncFuzzDirectories(target: str, save_location: str, base_url: str):
    """
    Directory fuzzing with ffuf against base_url/FUZZ.
    Launches in a separate console window, writing wrapper under the real user's home.
    """
    if not fncEnsureInstalled("ffuf", "e.g., apt install ffuf"):
        return

    fncPrintMessage(f"Directory fuzz → {base_url}/FUZZ", "info")

    # choose wordlist
    if input("Custom wordlist? (y/n): ").strip().lower() == "y":
        wordlist = input("Path to wordlist: ").strip()
    else:
        dirb_base = "/usr/share/wordlists/dirb"
        candidates = []
        if os.path.isdir(dirb_base):
            for fn in sorted(os.listdir(dirb_base)):
                if fn.lower().endswith((".txt", ".lst")):
                    candidates.append(os.path.join(dirb_base, fn))
        if candidates:
            print("Select a Dirb wordlist:")
            for i, p in enumerate(candidates, 1):
                print(f"  {i}) {os.path.basename(p)}")
            print(f"  {len(candidates)+1}) Other path")
            sel = input(f"[1-{len(candidates)+1}]: ").strip()
            try:
                idx = int(sel)
                if 1 <= idx <= len(candidates):
                    wordlist = candidates[idx - 1]
                else:
                    wordlist = input("Enter custom wordlist path: ").strip()
            except Exception:
                wordlist = input("Enter custom wordlist path: ").strip()
        else:
            wordlist = DOM_LIST

    if not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    # determine wrapper directory under real user's home if sudo
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        user_home = pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir
        base_dir = os.path.join(user_home, ".rs2nm")
    else:
        base_dir = os.path.expanduser("~/.rs2nm")

    wrapper_dir = os.path.join(base_dir, "wrappers", target)
    os.makedirs(wrapper_dir, exist_ok=True)
    wrapper = os.path.join(wrapper_dir, "ffuf_dirs_wrapper.py")

    with open(wrapper, "w", encoding="utf-8") as w:
        w.write(f'''#!/usr/bin/env python3
import sys, subprocess, signal, os
if len(sys.argv) < 5:
    print("Usage: ffuf_dirs_wrapper.py <target> <save_location> <base_url> <wordlist>")
    input("Press Enter to exit…")
    sys.exit(1)
target, save_location, base_url, wordlist = sys.argv[1:5]
output = os.path.join(save_location, f"{{target}}_dirs.json")
cmd = ["ffuf", "-s",
       "-u", f"{{base_url}}/FUZZ",
       "-w", f"{{wordlist}}:FUZZ",
       "-of", "json", "-t", "500", "-fc", "403", "-ac", "-v"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
signal.signal(signal.SIGINT, lambda s,f: proc.terminate())
lines = []
for line in proc.stdout:
    print(line, end="")
    lines.append(line)
proc.wait()
with open(output, "w", encoding="utf-8") as wf:
    wf.writelines(lines)
print(f"Results saved → {{output}}")
input("Press Enter to exit…")
''')
    os.chmod(wrapper, 0o755)

    args = [target, save_location, base_url, wordlist]
    if IS_WINDOWS:
        subprocess.Popen(
            [sys.executable, wrapper, *args],
            creationflags=CREATE_NEW_CONSOLE
        )
    else:
        fncLaunchInNewTerminal(wrapper, args)


def fncFuzzSubdomains(target: str, save_location: str, base_url: str):
    """
    Subdomain fuzzing with ffuf (Host header) in its own console window.
    Downloads a Nokovo wordlist if needed, writes a small wrapper under the real
    user's ~/.rs2nm/wrappers/<target>/ and launches it via fncLaunchInNewTerminal.
    """
    import os, pwd, urllib.request, platform
    from core.utils import fncPrintMessage
    from core.handlers import fncEnsureInstalled, fncLaunchInNewTerminal

    IS_WINDOWS = platform.system().lower() == "windows"

    # 1) Ensure ffuf is installed
    if not fncEnsureInstalled("ffuf", "e.g., apt install ffuf"):
        return

    fncPrintMessage(f"Subdomain fuzz → FUZZ.{target}", "info")

    # 2) Choose Nokovo list size or custom
    sizes = ["huge", "large", "medium", "small", "tiny"]
    for i, sz in enumerate(sizes, 1):
        print(f"  {i}) n0kovo_subdomains_{sz}.txt")
    print(f"  {len(sizes)+1}) Provide custom path")
    choice = input(f"[1-{len(sizes)+1}]: ").strip()
    try:
        idx = int(choice)
    except ValueError:
        idx = 1

    if 1 <= idx <= len(sizes):
        sz = sizes[idx - 1]
        wordlist = os.path.expanduser(f"~/.rs2nm/nokovo_subdomains_{sz}.txt")
        if not os.path.isfile(wordlist):
            fncPrintMessage(f"Downloading Nokovo ({sz})…", "info")
            os.makedirs(os.path.dirname(wordlist), exist_ok=True)
            url = (
                "https://raw.githubusercontent.com/"
                "n0kovo/n0kovo_subdomains/main/"
                f"n0kovo_subdomains_{sz}.txt"
            )
            try:
                urllib.request.urlretrieve(url, wordlist)
                fncPrintMessage(f"Saved → {wordlist}", "success")
            except KeyboardInterrupt:
                fncPrintMessage("Interrupted by user. Aborting download.", "warning")
                try: os.remove(wordlist)
                except: pass
                return
            except Exception as e:
                fncPrintMessage(f"Download failed: {e}", "error")
                wordlist = input("Enter custom wordlist path: ").strip()
    else:
        wordlist = input("Enter custom wordlist path: ").strip()

    if not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    # 3) Figure out base ~/.rs2nm for wrappers (handles sudo)
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        user_home = pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir
        base_dir  = os.path.join(user_home, ".rs2nm")
    else:
        base_dir  = os.path.expanduser("~/.rs2nm")

    wrapper_dir = os.path.join(base_dir, "wrappers", target)
    os.makedirs(wrapper_dir, exist_ok=True)
    wrapper = os.path.join(wrapper_dir, "ffuf_subs_wrapper.py")

    # 4) Write wrapper
    with open(wrapper, "w", encoding="utf-8") as f:
        f.write(f'''#!/usr/bin/env python3
import sys, subprocess, signal, os, urllib.request

# Debug: print args if count mismatches
if len(sys.argv) != 5:
    print("argv:", sys.argv)
    print("Usage: ffuf_subs_wrapper.py <target> <save_location> <base_url> <wordlist>")
    input("Press Enter to exit…")
    sys.exit(1)

target, save_location, base_url, wordlist = sys.argv[1:]
output = os.path.join(save_location, f"{{target}}_subs.json")

cmd = [
    "ffuf", "-s",
    "-w", f"{{wordlist}}:FUZZ",
    "-u", f"{{base_url}}/",
    "-H", f"Host: FUZZ.{{target}}",
    "-of", "json", "-t", "500", "-fc", "403", "-ac", "-v"
]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
signal.signal(signal.SIGINT, lambda s,f: proc.terminate())

lines = []
for line in proc.stdout:
    print(line, end="")
    lines.append(line)
proc.wait()

with open(output, "w", encoding="utf-8") as wf:
    wf.writelines(lines)

print(f"Results saved → {{output}}")
input("Press Enter to exit…")
''')
    os.chmod(wrapper, 0o755)

    # 5) Launch it
    args = [target, save_location, base_url, wordlist]
    if IS_WINDOWS:
        subprocess.Popen([sys.executable, wrapper, *args],
                         creationflags=CREATE_NEW_CONSOLE)
    else:
        fncLaunchInNewTerminal(wrapper, args)



def fncRunWebFuzz(target: str, save_location: str):
    """
    Full web enumeration:
      • Ensure hosts entry
      • Pick HTTP/S port
      • Run all web scans
    """
    fncPrintMessage("Starting full web enumeration…", "info")
    host = fncEnsureHostEntry(target)

    port = fncGetWebPort(host)
    if port == "443":
        base_url = f"https://{host}"
    else:
        base_url = f"http://{host}:{port}"

    fncPrintMessage(f"Using base URL: {base_url}", "info")

    # 3) Run web enumeration modules
    fncFuzzDirectories(host, save_location, base_url)
    fncFuzzSubdomains(host, save_location, base_url)
    """fncScanRobotsTxt(host, save_location, base_url)
    fncScanSitemapXml(host, save_location, base_url)
    fncScanHeaders(host, save_location, base_url)
    fncScanWafW00f(host, save_location, base_url)
    fncScanParams(host, save_location, base_url)
    fncScanCORS(host, save_location, base_url)
    fncScanCMSmap(host, save_location)
    fncScanSwagger(host, save_location, base_url)"""