#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import ctypes
from core.network.process import get_process_info

def is_process_elevated(pid):
    system = platform.system().lower()
    try:
        if system == 'windows':
            PROCESS_QUERY_INFORMATION = 0x0400
            TOKEN_QUERY = 0x0008
            hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not hProcess: return False
            
            hToken = ctypes.wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
                ctypes.windll.kernel32.CloseHandle(hProcess)
                return False
            
            class TOKEN_ELEVATION(ctypes.Structure):
                _fields_ = [("TokenIsElevated", ctypes.wintypes.DWORD)]
            
            elevation = TOKEN_ELEVATION()
            size = ctypes.sizeof(TOKEN_ELEVATION)
            success = ctypes.windll.advapi32.GetTokenInformation(hToken, 20, ctypes.byref(elevation), size, ctypes.byref(ctypes.wintypes.DWORD()))
            
            ctypes.windll.kernel32.CloseHandle(hToken)
            ctypes.windll.kernel32.CloseHandle(hProcess)
            return bool(elevation.TokenIsElevated) if success else False
        else:
        
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith('Uid:'):
                        return int(line.split()[1]) == 0
    except:
        return False

def audit_privileged_ports(connections):
    violations = []
    listening = [c for c in connections if c.get('state') in ('LISTEN', 'LISTENING')]
    
    for c in listening:
        port = c.get('local_port')
        pid = c.get('pid')
        
        if port and port < 1024 and pid:
            if not is_process_elevated(pid):
                p_info = get_process_info(pid)
                violations.append({
                    'pid': pid,
                    'port': port,
                    'name': p_info['name'] if p_info else 'Unknown',
                    'user': p_info['user'] if p_info else 'Unknown'
                })
    return violations