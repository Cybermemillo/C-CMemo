"""
Módulo de shell interactiva.
Proporciona una shell persistente con capacidades avanzadas.
"""

import os
import pty
import select
import socket
import subprocess
import threading
import time
import logging
import platform
import queue
from typing import Optional, Tuple, Any

class InteractiveShell:
    def __init__(self):
        """Inicializa la shell interactiva."""
        self.shell_proc = None
        self.is_windows = platform.system().lower() == "windows"
        self.running = False
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.last_activity = time.time()
        self.timeout = 300  # 5 minutos de timeout por defecto

    def start(self) -> bool:
        """
        Inicia la shell interactiva.
        
        Returns:
            bool: True si se inició correctamente
        """
        try:
            if self.is_windows:
                self.shell_proc = subprocess.Popen(
                    ["cmd.exe"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                # Usar pty para shells en Unix
                master, slave = pty.openpty()
                self.shell_proc = subprocess.Popen(
                    ["/bin/bash", "-i"],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    text=True
                )
                os.close(slave)
                self.master = master

            self.running = True
            
            # Iniciar threads de lectura/escritura
            threading.Thread(target=self._read_output, daemon=True).start()
            threading.Thread(target=self._process_commands, daemon=True).start()
            threading.Thread(target=self._check_timeout, daemon=True).start()
            
            return True
            
        except Exception as e:
            logging.error(f"Error iniciando shell interactiva: {e}")
            return False

    def stop(self):
        """Detiene la shell interactiva."""
        self.running = False
        if self.shell_proc:
            self.shell_proc.terminate()
            self.shell_proc = None

    def execute(self, command: str) -> None:
        """
        Encola un comando para ejecución.
        
        Args:
            command: Comando a ejecutar
        """
        self.last_activity = time.time()
        self.command_queue.put(command)

    def get_output(self, timeout: float = 0.1) -> Optional[str]:
        """
        Obtiene la salida pendiente de la shell.
        
        Args:
            timeout: Tiempo máximo de espera
            
        Returns:
            str: Salida de la shell o None si no hay datos
        """
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _read_output(self):
        """Lee continuamente la salida de la shell."""
        while self.running:
            try:
                if self.is_windows:
                    output = self.shell_proc.stdout.readline()
                    if output:
                        self.output_queue.put(output)
                else:
                    # Lectura no bloqueante para Unix
                    r, _, _ = select.select([self.master], [], [], 0.1)
                    if r:
                        output = os.read(self.master, 1024).decode()
                        if output:
                            self.output_queue.put(output)
            except Exception as e:
                logging.error(f"Error leyendo salida de shell: {e}")
                time.sleep(0.1)

    def _process_commands(self):
        """Procesa comandos pendientes."""
        while self.running:
            try:
                cmd = self.command_queue.get(timeout=0.1)
                if not cmd:
                    continue

                if self.is_windows:
                    self.shell_proc.stdin.write(f"{cmd}\n")
                    self.shell_proc.stdin.flush()
                else:
                    os.write(self.master, f"{cmd}\n".encode())
                    
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error procesando comando: {e}")

    def _check_timeout(self):
        """Verifica timeouts de inactividad."""
        while self.running:
            if time.time() - self.last_activity > self.timeout:
                logging.info("Shell terminada por inactividad")
                self.stop()
                break
            time.sleep(1)

    def is_alive(self) -> bool:
        """
        Verifica si la shell sigue activa.
        
        Returns:
            bool: True si la shell está activa
        """
        return self.running and self.shell_proc and self.shell_proc.poll() is None

    def set_timeout(self, seconds: int):
        """
        Establece el timeout de inactividad.
        
        Args:
            seconds: Segundos de inactividad permitidos
        """
        self.timeout = seconds

    def reset(self) -> bool:
        """
        Reinicia la shell.
        
        Returns:
            bool: True si se reinició correctamente
        """
        self.stop()
        return self.start()
