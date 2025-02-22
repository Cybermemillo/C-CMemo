"""
Módulo de ejecución de comandos.
Permite ejecutar comandos del sistema operativo y capturar su salida.
"""

import subprocess
import shlex
import os
import logging
from typing import Tuple, Optional
import platform
import tempfile
from pathlib import Path

class CommandExecutor:
    def __init__(self):
        """Inicializa el ejecutor de comandos."""
        self.is_windows = platform.system().lower() == 'windows'
        self.default_shell = 'cmd.exe' if self.is_windows else '/bin/bash'
        self.powershell_path = self._find_powershell()

    def _find_powershell(self) -> str:
        """Localiza la ruta de PowerShell en el sistema."""
        if not self.is_windows:
            return ""
            
        possible_paths = [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\PowerShell\v1.0\powershell.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe"  # PowerShell Core
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return "powershell.exe"  # fallback to PATH lookup

    def execute_cmd(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        Ejecuta un comando usando CMD.exe.
        
        Args:
            command: Comando a ejecutar
            timeout: Tiempo máximo de ejecución en segundos
            
        Returns:
            Tupla con (código_retorno, stdout, stderr)
        """
        try:
            if not self.is_windows:
                raise RuntimeError("CMD.exe solo está disponible en Windows")
                
            process = subprocess.Popen(
                ['cmd.exe', '/c', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr
            
        except subprocess.TimeoutExpired:
            process.kill()
            return -1, "", "Command timed out"
        except Exception as e:
            logging.error(f"Error ejecutando comando CMD: {e}")
            return -1, "", str(e)

    def execute_powershell(self, 
                          command: str, 
                          timeout: int = 30,
                          encoded: bool = False) -> Tuple[int, str, str]:
        """
        Ejecuta un comando usando PowerShell.
        
        Args:
            command: Comando o script a ejecutar
            timeout: Tiempo máximo de ejecución en segundos
            encoded: Si True, codifica el comando en Base64
            
        Returns:
            Tupla con (código_retorno, stdout, stderr)
        """
        try:
            if not self.is_windows:
                raise RuntimeError("PowerShell solo está disponible en Windows")

            if encoded:
                # Codificar comando en Base64 para evitar problemas con caracteres especiales
                encoded_command = command.encode('utf-16le')
                command = f'-EncodedCommand {encoded_command.hex()}'
            
            process = subprocess.Popen(
                [self.powershell_path, '-NoProfile', '-NonInteractive', '-Command', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr
            
        except subprocess.TimeoutExpired:
            process.kill()
            return -1, "", "Command timed out"
        except Exception as e:
            logging.error(f"Error ejecutando comando PowerShell: {e}")
            return -1, "", str(e)

    def execute_script(self, script_content: str, script_type: str = "ps1") -> Tuple[int, str, str]:
        """
        Ejecuta un script desde una cadena de texto.
        
        Args:
            script_content: Contenido del script
            script_type: Tipo de script (ps1, bat, vbs)
            
        Returns:
            Tupla con (código_retorno, stdout, stderr)
        """
        try:
            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix=f'.{script_type}',
                delete=False,
                encoding='utf-8'
            ) as temp_file:
                temp_file.write(script_content)
                temp_path = temp_file.name

            try:
                if script_type == "ps1":
                    return self.execute_powershell(f". '{temp_path}'")
                elif script_type == "bat":
                    return self.execute_cmd(temp_path)
                elif script_type == "vbs":
                    return self.execute_cmd(f'cscript //NoLogo "{temp_path}"')
                else:
                    raise ValueError(f"Tipo de script no soportado: {script_type}")
            finally:
                # Limpiar archivo temporal
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"Error ejecutando script: {e}")
            return -1, "", str(e)
