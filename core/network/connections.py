from core.platform.platform_utils import IS_WINDOWS, IS_LINUX, IS_MAC
from .parser import parse_ss_output, parse_netstat_linux, parse_netstat_macos, parse_netstat_windows
import subprocess
import locale

def run_command(cmd):
    try:
        enc = locale.getpreferredencoding(False)
        result = subprocess.run(cmd, capture_output=True, text=True, encoding=enc, errors='replace', shell=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

def get_connections():
    if IS_WINDOWS:
        out = run_command("netstat -ano")
        return parse_netstat_windows(out)
    elif IS_LINUX:
        out = run_command("ss -tunap 2>/dev/null")
        return parse_ss_output(out)
    elif IS_MAC:
        out = run_command("netstat -anv 2>/dev/null")
        return parse_netstat_macos(out)
    return []