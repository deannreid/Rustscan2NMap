import hashlib
import json
import os
import re
import urllib.request
from getpass import getpass

from core.handlers import fncEnsureInstalled
from core.utils    import fncPrintMessage

PW_URL       = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/passwords100k.pr0be"
PW_SUM_URL   = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/passwords100k.pr0be.sha256"
USER_URL     = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/usernames45k.pr0be"
USER_SUM_URL = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/usernames45k.pr0be.sha256"

SQL_PORTS = {
    3306: "mysql",
    5432: "postgres"
}


def fncParseNmapFile(nmap_path_or_host):
    services = {}

    if os.path.isfile(nmap_path_or_host):
        port_re = re.compile(r'^(\d+)/tcp\s+open')
        try:
            with open(nmap_path_or_host, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = port_re.match(line)
                    if m:
                        port = int(m.group(1))
                        if port in SQL_PORTS:
                            services[SQL_PORTS[port]] = port
            return services
        except Exception as e:
            fncPrintMessage(f"Error reading Nmap file: {e}", "warning")

    host = os.path.basename(nmap_path_or_host)
    meta = os.path.expanduser(f"~/.rs2nm/temp/rs2nm_{host}.json")
    if not os.path.isfile(meta):
        fncPrintMessage(f"Nmap file not found and no metadata at {meta}", "error")
        return services

    try:
        with open(meta, "r", encoding="utf-8") as jf:
            data = json.load(jf)
        for p in data.get("ports", "").split(","):
            p = p.strip()
            if p:
                try:
                    port = int(p)
                    if port in SQL_PORTS:
                        services[SQL_PORTS[port]] = port
                except ValueError:
                    continue
    except Exception as e:
        fncPrintMessage(f"Error reading metadata: {e}", "error")

    return services


def _compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def fncDownloadIfNeeded(url: str, checksum_url: str, local_path: str):
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    need = True
    if os.path.isfile(local_path):
        try:
            local_sum  = _compute_sha256(local_path)
            remote_sum = urllib.request.urlopen(checksum_url, timeout=10).read().decode().strip()
            if local_sum == remote_sum:
                fncPrintMessage(f"{os.path.basename(local_path)} is up to date.", "info")
                need = False
        except Exception:
            need = True

    if need:
        fncPrintMessage(f"Downloading {os.path.basename(local_path)}…", "info")
        try:
            urllib.request.urlretrieve(url, local_path)
            fncPrintMessage(f"Saved → {local_path}", "success")
        except Exception as e:
            fncPrintMessage(f"Download failed: {e}", "error")
            raise


def fncTryLoginMySQL(host, port, user, password):
    try:
        import pymysql
    except ImportError:
        fncPrintMessage("pymysql not installed. Run: pip install pymysql", "error")
        return None
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=5)
        fncPrintMessage(f"MySQL login succeeded for '{user}'", "success")
        return conn
    except Exception as e:
        fncPrintMessage(f"MySQL login failed: {e}", "warning")
        return None


def fncTryLoginPostgres(host, port, user, password):
    try:
        import psycopg2
    except ImportError:
        fncPrintMessage("psycopg2 not installed. Run: pip install psycopg2", "error")
        return None
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=5)
        fncPrintMessage(f"PostgreSQL login succeeded for '{user}'", "success")
        return conn
    except Exception as e:
        fncPrintMessage(f"PostgreSQL login failed: {e}", "warning")
        return None


def fncPrivilegeInfoMySQL(conn):
    fncPrintMessage("Gathering MySQL privilege info…", "info")
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW VARIABLES LIKE 'secure_file_priv';")
            priv = cur.fetchone()
            fncPrintMessage(f"secure_file_priv = {priv}", "info")
    except Exception as e:
        fncPrintMessage(f"MySQL privilege info error: {e}", "error")


def fncPrivilegeInfoPostgres(conn):
    fncPrintMessage("Gathering PostgreSQL directory info…", "info")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('data_directory');")
            ddir = cur.fetchone()
            fncPrintMessage(f"data_directory = {ddir}", "info")
    except Exception as e:
        fncPrintMessage(f"Postgres privilege info error: {e}", "error")


def fncBruteForce(service, host, port, users, pwds):
    fncPrintMessage(f"Brute-forcing {service} at {host}:{port}", "info")
    login_fn = fncTryLoginMySQL if service == "mysql" else fncTryLoginPostgres
    for u in users:
        for p in pwds:
            conn = login_fn(host, port, u.strip(), p.strip())
            if conn:
                return u.strip(), p.strip(), conn
    return None, None, None


def fncRunSQLEnum(nmap_file, host):
    services = fncParseNmapFile(nmap_file)
    if not services:
        fncPrintMessage("No SQL services detected.", "warning")
        return

    fncPrintMessage(f"Detected SQL services: {services}", "info")

    bf_dir    = os.path.expanduser("~/.rs2nm/bin/sql")
    pw_file   = os.path.join(bf_dir, "passwords100k.pr0be")
    user_file = os.path.join(bf_dir, "usernames45k.pr0be")

    for svc, port in services.items():
        conn = None
        if input(f"Have credentials for {svc}? (y/n): ").strip().lower() == "y":
            user = input("Username: ").strip()
            pwd  = getpass("Password: ")
            conn = (fncTryLoginMySQL if svc == "mysql" else fncTryLoginPostgres)(host, port, user, pwd)
        else:
            if input("Brute-force superuser? (y/n): ").strip().lower() == "y":
                try:
                    fncDownloadIfNeeded(PW_URL,   PW_SUM_URL,   pw_file)
                    fncDownloadIfNeeded(USER_URL, USER_SUM_URL, user_file)
                except Exception:
                    fncPrintMessage("Could not obtain wordlists; skipping brute-force.", "error")
                    continue
                with open(user_file, "r", errors="ignore") as uf:
                    users = uf.read().splitlines()
                with open(pw_file, "r", errors="ignore") as pf:
                    pwds = pf.read().splitlines()
                u, p, conn = fncBruteForce(svc, host, port, users, pwds)
                if conn:
                    fncPrintMessage(f"Brute-force succeeded: {u}/{p}", "success")

        if conn:
            fncPrintMessage(f"Connected to {svc}; gathering info…", "success")
            if svc == "mysql":
                fncPrivilegeInfoMySQL(conn)
            else:
                fncPrivilegeInfoPostgres(conn)
            conn.close()
        else:
            fncPrintMessage(f"No valid credentials found for {svc}.", "warning")
