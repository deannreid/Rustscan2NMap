import sys
import os
import platform
import ctypes
from colorama import Fore, Style

def fncPrintMessage(message, msg_type="info"):
    symbols = {
        "info": Fore.CYAN + "{~} ",
        "warning": Fore.YELLOW + "{!} ",
        "success": Fore.GREEN + "{✓} ",
        "error": Fore.RED + "{!} ",
        "disabled": Fore.LIGHTBLACK_EX + "{X} "
    }
    prefix = symbols.get(msg_type, "")
    print(prefix + message + Style.RESET_ALL)


def fncIsAdmin():
    system = platform.system().lower()
    if system == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            fncPrintMessage(f"Could not determine admin privileges: {e}", "error")
            sys.exit(1)
    else:
        return os.geteuid() == 0


def fncCheckPythonVersion():
    python_version = sys.version_info
    fncPrintMessage(f"Python Version Detected: {platform.python_version()}", "info")
    if python_version < (3, 10):
        fncPrintMessage("Python 3.10+ is required. Please upgrade your Python.", "error")
        sys.exit(1)
