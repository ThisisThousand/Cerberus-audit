from .connections import run_command
from core.platform.platform_utils import IS_WINDOWS

def get_process_info(pid):
    if pid is None or pid == 0:
        return {
            "name": "System/Idle",
            "pid": 0,
            "user": "SYSTEM",
            "commandline": "Kernel Process"
        }

    if IS_WINDOWS:
        return _get_windows_process_info(pid)
    else:
        return _get_unix_process_info(pid)

def _get_windows_process_info(pid):
    """Extrae datos en Windows usando tasklist y wmic."""
    info = {"pid": pid, "name": "Unknown", "user": "Unknown", "commandline": "N/A"}
    task_out = run_command(f'tasklist /v /fi "PID eq {pid}" /fo csv')
    lines = task_out.strip().split('\n')
    
    if len(lines) >= 2:
        parts = [p.strip('"') for p in lines[1].split(',')]
        if len(parts) >= 6:
            info["name"] = parts[0]
            info["user"] = parts[5]

    cmd_out = run_command(f'wmic process where processid={pid} get commandline /format:list')
    if "CommandLine=" in cmd_out:
        info["commandline"] = cmd_out.split("CommandLine=", 1)[1].strip()
        
    return info

def _get_unix_process_info(pid):
    info = {"pid": pid, "name": "Unknown", "user": "Unknown", "commandline": "N/A"}
    ps_out = run_command(f'ps -p {pid} -o pid,comm,user,args --no-headers 2>/dev/null')
    
    if ps_out and "Error" not in ps_out:
        parts = ps_out.strip().split(None, 3)
        if len(parts) >= 4:
            info["name"] = parts[1]
            info["user"] = parts[2]
            info["commandline"] = parts[3]
            
    return info