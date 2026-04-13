import platform
import os
import sys
import ctypes


SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == 'windows'
IS_LINUX = SYSTEM == 'linux'
IS_MAC = SYSTEM == 'darwin'


if IS_WINDOWS:
    from ctypes import wintypes

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.DWORD),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", wintypes.INT),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hKeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hMonitor", ctypes.c_void_p),
            ("hProcess", wintypes.HANDLE),
        ]

def is_admin():
    """Verifica si el proceso actual tiene privilegios de administrador/root."""
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # En Unix/Linux/Mac, el UID 0 es root
        return os.geteuid() == 0

def ensure_admin_privileges():
    """
    Verifica si el usuario tiene privilegios de administrador.
    En Windows, si no los tiene, intenta relanzar el script.
    """
    if IS_WINDOWS:
        if not is_admin():
            from rich import print as rprint
            rprint("[bold yellow]Solicitando privilegios de administrador...[/bold yellow]")
            # Intentamos relanzar y salimos del proceso actual
            sys.exit(run_as_admin_and_wait())
    else:
        # Lógica para Linux/macOS si fuera necesario (sudo check)
        if os.geteuid() != 0:
            from rich import print as rprint
            rprint("[bold red]⚠ Advertencia: Cerberus funciona mejor con privilegios de ROOT (sudo).[/bold red]")





def run_as_admin_and_wait():
    """
    Intenta relanzar el script con privilegios elevados en Windows 
    y espera a que el proceso hijo termine.
    """
    if not IS_WINDOWS:
        return 1

    script_path = os.path.abspath(sys.argv[0])
    python_exe = sys.executable
    
    # Preparamos los argumentos citándolos si contienen espacios
    args = [script_path] + sys.argv[1:]
    args_quoted = [f'"{a}"' if ' ' in a else a for a in args]
    params = ' '.join(args_quoted)

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    sei.fMask = 0x00000040  
    sei.hwnd = None
    sei.lpVerb = "runas"    
    sei.lpFile = python_exe
    sei.lpParameters = params
    sei.lpDirectory = os.path.dirname(script_path)
    sei.nShow = 1           
    sei.hProcess = None

    success = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    
    if not success:
        error = ctypes.GetLastError()
        print(f"Error al solicitar elevación (código {error}).")
        return 1

    if sei.hProcess:
        
        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
        exit_code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        return exit_code.value
    else:
        print("No se pudo obtener el handle del proceso elevado.")
        return 1