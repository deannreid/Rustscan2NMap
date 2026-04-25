#!/usr/bin/env python3
import os
import ssl
import sys
import socket
import subprocess
import platform
import urllib.request

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

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _http_get(url: str, extra_headers: dict = None, timeout: int = 10):
    headers = {"User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX)


def fncGetWebPort(target: str) -> str:
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
    return input("Neither 80 nor 443 open — enter port to use: ").strip()


def fncFuzzDirectories(target: str, save_location: str, base_url: str):
    if not fncEnsureInstalled("ffuf", "apt install ffuf"):
        return

    fncPrintMessage(f"Directory fuzz → {base_url}/FUZZ", "info")

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
                wordlist = candidates[idx - 1] if 1 <= idx <= len(candidates) else input("Enter custom wordlist path: ").strip()
            except Exception:
                wordlist = input("Enter custom wordlist path: ").strip()
        else:
            wordlist = DOM_LIST

    if not wordlist or not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    wrapper = _get_wrapper_path(target, "ffuf_dirs_wrapper.py")
    with open(wrapper, "w", encoding="utf-8") as w:
        w.write(f'''#!/usr/bin/env python3
import sys, subprocess, signal, os
if len(sys.argv) < 5:
    print("Usage: ffuf_dirs_wrapper.py <target> <save_location> <base_url> <wordlist>")
    input("Press Enter to exit…")
    sys.exit(1)
target, save_location, base_url, wordlist = sys.argv[1:5]
output = os.path.join(save_location, f"{{target}}_dirs.json")
cmd = ["ffuf", "-s", "-u", f"{{base_url}}/FUZZ", "-w", f"{{wordlist}}:FUZZ",
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
    _chmod_wrapper(wrapper)
    _launch_wrapper(wrapper, [target, save_location, base_url, wordlist])


def fncFuzzSubdomains(target: str, save_location: str, base_url: str):
    if not fncEnsureInstalled("ffuf", "apt install ffuf"):
        return

    fncPrintMessage(f"Subdomain fuzz → FUZZ.{target}", "info")

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
            fncPrintMessage(f"Downloading n0kovo ({sz})…", "info")
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
                fncPrintMessage("Download interrupted.", "warning")
                try:
                    os.remove(wordlist)
                except OSError:
                    pass
                return
            except Exception as e:
                fncPrintMessage(f"Download failed: {e}", "error")
                wordlist = input("Enter custom wordlist path: ").strip()
    else:
        wordlist = input("Enter custom wordlist path: ").strip()

    if not wordlist or not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    wrapper = _get_wrapper_path(target, "ffuf_subs_wrapper.py")
    with open(wrapper, "w", encoding="utf-8") as f:
        f.write(f'''#!/usr/bin/env python3
import sys, subprocess, signal, os
if len(sys.argv) != 5:
    print("Usage: ffuf_subs_wrapper.py <target> <save_location> <base_url> <wordlist>")
    input("Press Enter to exit…")
    sys.exit(1)
target, save_location, base_url, wordlist = sys.argv[1:]
output = os.path.join(save_location, f"{{target}}_subs.json")
cmd = ["ffuf", "-s", "-w", f"{{wordlist}}:FUZZ", "-u", f"{{base_url}}/",
       "-H", f"Host: FUZZ.{{target}}", "-of", "json", "-t", "500", "-fc", "403", "-ac", "-v"]
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
    _chmod_wrapper(wrapper)
    _launch_wrapper(wrapper, [target, save_location, base_url, wordlist])


def fncScanRobotsTxt(target: str, save_location: str, base_url: str):
    url = f"{base_url}/robots.txt"
    fncPrintMessage(f"Fetching {url}…", "info")
    output_file = os.path.join(save_location, f"{target}_robots.txt")
    try:
        with _http_get(url) as r:
            content = r.read().decode("utf-8", errors="replace")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        fncPrintMessage(f"robots.txt saved → {output_file}", "success")
        preview = content[:500].strip()
        if preview:
            print(preview)
    except Exception as e:
        fncPrintMessage(f"robots.txt: {e}", "warning")


def fncScanSitemapXml(target: str, save_location: str, base_url: str):
    url = f"{base_url}/sitemap.xml"
    fncPrintMessage(f"Fetching {url}…", "info")
    output_file = os.path.join(save_location, f"{target}_sitemap.xml")
    try:
        with _http_get(url) as r:
            content = r.read().decode("utf-8", errors="replace")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        fncPrintMessage(f"sitemap.xml saved → {output_file}", "success")
    except Exception as e:
        fncPrintMessage(f"sitemap.xml: {e}", "warning")


def fncScanHeaders(target: str, save_location: str, base_url: str):
    fncPrintMessage(f"Checking HTTP headers for {base_url}…", "info")
    output_file = os.path.join(save_location, f"{target}_headers.txt")
    try:
        with _http_get(base_url) as r:
            headers = dict(r.headers)
        with open(output_file, "w", encoding="utf-8") as f:
            for k, v in headers.items():
                f.write(f"{k}: {v}\n")
        fncPrintMessage(f"Headers saved → {output_file}", "success")
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        info_headers = ["Server", "X-Powered-By"]
        for h in info_headers:
            if h in headers:
                fncPrintMessage(f"  {h}: {headers[h]}", "warning")
        for h in security_headers:
            if h in headers:
                fncPrintMessage(f"  {h}: {headers[h]}", "success")
            else:
                fncPrintMessage(f"  {h}: MISSING", "warning")
    except Exception as e:
        fncPrintMessage(f"Header check failed: {e}", "warning")


def fncScanCORS(target: str, save_location: str, base_url: str):
    fncPrintMessage("Testing CORS configuration…", "info")
    output_file = os.path.join(save_location, f"{target}_cors.txt")
    try:
        with _http_get(base_url, extra_headers={"Origin": "https://evil.com"}) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
        result = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}\n"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)
        if acao in ("*", "https://evil.com"):
            fncPrintMessage(f"Permissive CORS detected: ACAO={acao!r}", "warning")
        else:
            fncPrintMessage(f"CORS ACAO: {acao or 'not set'}", "info")
    except Exception as e:
        fncPrintMessage(f"CORS check failed: {e}", "warning")


def fncScanWafW00f(target: str, save_location: str, base_url: str):
    if not fncEnsureInstalled("wafw00f", "pip install wafw00f"):
        return
    fncPrintMessage("Running wafw00f WAF detection…", "info")
    output_file = os.path.join(save_location, f"{target}_wafw00f.txt")
    try:
        proc = subprocess.Popen(
            ["wafw00f", base_url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = proc.communicate(timeout=60)
        decoded = out.decode("utf-8", errors="replace")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(decoded)
        fncPrintMessage(f"wafw00f results → {output_file}", "success")
        print(decoded.strip())
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("wafw00f timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"wafw00f error: {e}", "error")


def fncScanParams(target: str, save_location: str, base_url: str):
    if not fncEnsureInstalled("arjun", "pip install arjun"):
        return
    fncPrintMessage("Running Arjun parameter discovery…", "info")
    output_file = os.path.join(save_location, f"{target}_params.json")
    try:
        proc = subprocess.Popen(
            ["arjun", "-u", base_url, "-oJ", output_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = proc.communicate(timeout=120)
        fncPrintMessage(f"Arjun results → {output_file}", "success")
        print(out.decode("utf-8", errors="replace").strip())
    except subprocess.TimeoutExpired:
        proc.kill()
        fncPrintMessage("Arjun timed out.", "warning")
    except Exception as e:
        fncPrintMessage(f"Arjun error: {e}", "error")


def fncScanCMSmap(target: str, save_location: str):
    if fncEnsureInstalled("whatweb", "apt install whatweb"):
        fncPrintMessage("Running whatweb CMS/tech detection…", "info")
        output_file = os.path.join(save_location, f"{target}_whatweb.txt")
        try:
            proc = subprocess.Popen(
                ["whatweb", "--color=never", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = proc.communicate(timeout=60)
            decoded = out.decode("utf-8", errors="replace")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(decoded)
            fncPrintMessage(f"whatweb results → {output_file}", "success")
            print(decoded.strip())
        except subprocess.TimeoutExpired:
            proc.kill()
            fncPrintMessage("whatweb timed out.", "warning")
        except Exception as e:
            fncPrintMessage(f"whatweb error: {e}", "error")
    elif fncEnsureInstalled("cmsmap", "pip install cmsmap"):
        fncPrintMessage("Running CMSmap…", "info")
        output_file = os.path.join(save_location, f"{target}_cmsmap.txt")
        try:
            proc = subprocess.Popen(
                ["cmsmap", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = proc.communicate(timeout=120)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out.decode("utf-8", errors="replace"))
            fncPrintMessage(f"CMSmap results → {output_file}", "success")
        except subprocess.TimeoutExpired:
            proc.kill()
            fncPrintMessage("CMSmap timed out.", "warning")
        except Exception as e:
            fncPrintMessage(f"CMSmap error: {e}", "error")


def fncScanSwagger(target: str, save_location: str, base_url: str):
    swagger_paths = [
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
    ]
    fncPrintMessage("Checking Swagger/OpenAPI endpoints…", "info")
    output_file = os.path.join(save_location, f"{target}_swagger.txt")
    found = []
    for path in swagger_paths:
        url = f"{base_url}{path}"
        try:
            with _http_get(url, timeout=5) as r:
                if r.status == 200:
                    found.append(url)
                    fncPrintMessage(f"Found: {url}", "success")
        except Exception:
            continue
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(found) + "\n" if found else "No Swagger endpoints found.\n")
    if not found:
        fncPrintMessage("No Swagger/OpenAPI endpoints found.", "info")


def fncRunWebFuzz(target: str, save_location: str):
    fncPrintMessage("Starting full web enumeration…", "info")
    host = fncEnsureHostEntry(target)

    port = fncGetWebPort(host)
    if port == "443":
        base_url = f"https://{host}"
    else:
        base_url = f"http://{host}:{port}"

    fncPrintMessage(f"Using base URL: {base_url}", "info")

    fncFuzzDirectories(host, save_location, base_url)
    fncFuzzSubdomains(host, save_location, base_url)
    fncScanRobotsTxt(host, save_location, base_url)
    fncScanSitemapXml(host, save_location, base_url)
    fncScanHeaders(host, save_location, base_url)
    fncScanCORS(host, save_location, base_url)
    fncScanWafW00f(host, save_location, base_url)
    fncScanParams(host, save_location, base_url)
    fncScanCMSmap(host, save_location)
    fncScanSwagger(host, save_location, base_url)


# ── helpers ────────────────────────────────────────────────────────────────

def _get_wrapper_path(target: str, filename: str) -> str:
    if IS_WINDOWS:
        base_dir = os.path.expanduser("~/.rs2nm")
    elif os.name != "nt" and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        try:
            import pwd
            user_home = pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir
            base_dir  = os.path.join(user_home, ".rs2nm")
        except (KeyError, ImportError):
            base_dir = os.path.expanduser("~/.rs2nm")
    else:
        base_dir = os.path.expanduser("~/.rs2nm")

    wrapper_dir = os.path.join(base_dir, "wrappers", target)
    os.makedirs(wrapper_dir, exist_ok=True)
    return os.path.join(wrapper_dir, filename)


def _chmod_wrapper(path: str):
    if os.name != "nt":
        os.chmod(path, 0o755)


def _launch_wrapper(wrapper: str, args: list):
    if IS_WINDOWS:
        subprocess.Popen(
            [sys.executable, wrapper, *args],
            creationflags=CREATE_NEW_CONSOLE
        )
    else:
        fncLaunchInNewTerminal(wrapper, args)
