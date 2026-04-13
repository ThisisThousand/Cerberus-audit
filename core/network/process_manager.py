import os
import signal
import platform
import subprocess
from core.network.process import get_process_info

def kill_process(pid, force=False):
    system = platform.system().lower()
    
    try:
        pid = int(pid)
        if pid <= 0:
            return False, f"PID inválido: {pid}"
    except (ValueError, TypeError):
        return False, f"PID inválido: {pid}"
    
    if system == 'windows':
        try:
            flags = ['/F'] if force else []
            cmd = ['taskkill'] + flags + ['/PID', str(pid)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return True, f"Proceso {pid} terminado."
            else:
                return False, result.stderr.strip()
        except Exception as e:
            return False, str(e)
    else:
        try:
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.kill(pid, sig)
            return True, f"Proceso {pid} terminado."
        except ProcessLookupError:
            return False, f"El proceso {pid} no existe."
        except PermissionError:
            return False, "Permiso denegado. Se requieren privilegios elevados."
        except Exception as e:
            return False, str(e)

def kill_process_interactive(pid, lang):
    if not str(pid).isdigit():
        return False, "PID inválido."
    
    pid = int(pid)
    proc_info = get_process_info(pid)
    
    print(f"\n[bold red]ADVERTENCIA:[/bold red] Vas a terminar el proceso PID: {pid}")
    if proc_info and proc_info.get('name') != "Unknown":
        print(f"   Nombre: {proc_info.get('name')}")
        print(f"   Usuario: {proc_info.get('user')}")
    
    confirm = input(f"\n¿Confirmar terminación del proceso {pid}? (s/N): ").strip().lower()
    if confirm not in ('s', 'si', 'sí', 'y', 'yes'):
        return False, "Operación cancelada."
    
    force_confirm = input("¿Forzar terminación (kill -9)? (s/N): ").strip().lower()
    force = force_confirm in ('s', 'si', 'sí', 'y', 'yes')
    
    return kill_process(pid, force=force)