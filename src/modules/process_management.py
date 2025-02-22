"""
Módulo de gestión de procesos.
Proporciona funcionalidades para listar, monitorear y controlar procesos del sistema.
"""

import psutil
import logging
import time
import platform
import os
import signal
from typing import List, Dict, Optional, Union
from datetime import datetime
import threading

class ProcessMonitor:
    def __init__(self):
        """Inicializa el monitor de procesos."""
        self.monitoring = False
        self.monitored_processes = set()
        self.monitor_thread = None
        self.callback = None
        self.suspicious_patterns = [
            "netcat", "nc.exe", "mimikatz", "psexec",
            "powersploit", "metasploit", "wireshark",
            "tcpdump", "nmap", "john", "hashcat"
        ]

    def list_processes(self) -> List[Dict[str, Union[int, str, float]]]:
        """
        Lista todos los procesos en ejecución con información detallada.
        
        Returns:
            Lista de diccionarios con información de cada proceso
        """
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 
                                          'memory_percent', 'username', 'status']):
                try:
                    info = proc.info
                    info['created_time'] = datetime.fromtimestamp(
                        proc.create_time()
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    info['command_line'] = " ".join(proc.cmdline()) if proc.cmdline() else ""
                    info['suspicious'] = any(pattern in info['name'].lower() 
                                          for pattern in self.suspicious_patterns)
                    processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return processes
        except Exception as e:
            logging.error(f"Error listando procesos: {e}")
            return []

    def get_process_info(self, pid: int) -> Optional[Dict[str, Union[int, str, float]]]:
        """
        Obtiene información detallada de un proceso específico.
        
        Args:
            pid: ID del proceso
            
        Returns:
            Diccionario con información detallada del proceso
        """
        try:
            proc = psutil.Process(pid)
            info = {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'username': proc.username(),
                'exe': proc.exe(),
                'cwd': proc.cwd(),
                'command_line': " ".join(proc.cmdline()),
                'connections': [conn._asdict() for conn in proc.connections()],
                'open_files': [file.path for file in proc.open_files()],
                'threads': proc.num_threads(),
                'parent': proc.parent().pid if proc.parent() else None,
                'children': [child.pid for child in proc.children()],
                'created_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'cpu_affinity': proc.cpu_affinity(),
                'memory_maps': [map._asdict() for map in proc.memory_maps()],
                'is_running': proc.is_running()
            }
            return info
        except psutil.NoSuchProcess:
            logging.warning(f"Proceso {pid} no encontrado")
            return None
        except Exception as e:
            logging.error(f"Error obteniendo información del proceso {pid}: {e}")
            return None

    def kill_process(self, pid: int, force: bool = False) -> bool:
        """
        Mata un proceso por su PID.
        
        Args:
            pid: ID del proceso a matar
            force: Si True, usa SIGKILL en lugar de SIGTERM
            
        Returns:
            bool indicando si se mató el proceso exitosamente
        """
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()  # SIGKILL
            else:
                proc.terminate()  # SIGTERM
            proc.wait(timeout=3)
            return True
        except psutil.NoSuchProcess:
            logging.warning(f"Proceso {pid} no encontrado")
            return False
        except Exception as e:
            logging.error(f"Error matando proceso {pid}: {e}")
            return False

    def kill_process_by_name(self, name: str, force: bool = False) -> List[int]:
        """
        Mata todos los procesos que coincidan con el nombre dado.
        
        Args:
            name: Nombre del proceso a matar
            force: Si True, usa SIGKILL en lugar de SIGTERM
            
        Returns:
            Lista de PIDs de los procesos terminados
        """
        killed_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == name.lower():
                    if self.kill_process(proc.info['pid'], force):
                        killed_pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return killed_pids

    def set_process_priority(self, pid: int, priority: int) -> bool:
        """
        Cambia la prioridad de un proceso.
        
        Args:
            pid: ID del proceso
            priority: Nueva prioridad (de -20 a 19 en Unix, 0-5 en Windows)
            
        Returns:
            bool indicando si se cambió la prioridad exitosamente
        """
        try:
            proc = psutil.Process(pid)
            if platform.system() == 'Windows':
                proc.nice(priority)
            else:
                os.setpriority(os.PRIO_PROCESS, pid, priority)
            return True
        except Exception as e:
            logging.error(f"Error cambiando prioridad del proceso {pid}: {e}")
            return False

    def start_monitoring(self, callback=None, interval: float = 1.0):
        """
        Inicia el monitoreo de procesos en tiempo real.
        
        Args:
            callback: Función a llamar cuando hay cambios en los procesos
            interval: Intervalo de monitoreo en segundos
        """
        if self.monitoring:
            return

        self.monitoring = True
        self.callback = callback

        def monitor_loop():
            previous_processes = set(p.pid for p in psutil.process_iter())
            
            while self.monitoring:
                try:
                    current_processes = set(p.pid for p in psutil.process_iter())
                    
                    # Detectar nuevos procesos
                    new_processes = current_processes - previous_processes
                    for pid in new_processes:
                        try:
                            proc = psutil.Process(pid)
                            if self.callback:
                                self.callback("new", {
                                    'pid': pid,
                                    'name': proc.name(),
                                    'cmdline': " ".join(proc.cmdline()),
                                    'username': proc.username(),
                                    'created': datetime.fromtimestamp(proc.create_time())
                                })
                        except psutil.NoSuchProcess:
                            continue
                    
                    # Detectar procesos terminados
                    terminated_processes = previous_processes - current_processes
                    for pid in terminated_processes:
                        if self.callback:
                            self.callback("terminated", {'pid': pid})
                    
                    previous_processes = current_processes
                    time.sleep(interval)
                    
                except Exception as e:
                    logging.error(f"Error en monitoreo de procesos: {e}")
                    time.sleep(interval)

        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Detiene el monitoreo de procesos."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)

    def find_suspicious_processes(self) -> List[Dict[str, Union[int, str]]]:
        """
        Busca procesos potencialmente sospechosos.
        
        Returns:
            Lista de procesos sospechosos con su información
        """
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                info = proc.info
                # Verificar patrones sospechosos
                if any(pattern in info['name'].lower() for pattern in self.suspicious_patterns):
                    suspicious.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cmdline': " ".join(info['cmdline']) if info['cmdline'] else "",
                        'username': info['username'],
                        'reason': 'suspicious_name'
                    })
                # Verificar uso alto de CPU
                elif proc.cpu_percent(interval=0.1) > 90:
                    suspicious.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu_percent': proc.cpu_percent(),
                        'reason': 'high_cpu'
                    })
                # Verificar conexiones de red sospechosas
                elif proc.connections():
                    for conn in proc.connections():
                        if conn.status == 'LISTEN' and conn.laddr.port < 1024:
                            suspicious.append({
                                'pid': info['pid'],
                                'name': info['name'],
                                'port': conn.laddr.port,
                                'reason': 'suspicious_port'
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious

    def get_process_tree(self, pid: int = None) -> Dict:
        """
        Obtiene el árbol de procesos desde un PID dado.
        Si no se proporciona PID, devuelve el árbol completo.
        
        Args:
            pid: ID del proceso raíz (opcional)
            
        Returns:
            Diccionario representando el árbol de procesos
        """
        def get_children(parent_pid):
            children = []
            try:
                parent = psutil.Process(parent_pid)
                for child in parent.children(recursive=False):
                    try:
                        children.append({
                            'pid': child.pid,
                            'name': child.name(),
                            'status': child.status(),
                            'children': get_children(child.pid)
                        })
                    except psutil.NoSuchProcess:
                        continue
            except psutil.NoSuchProcess:
                return children
            return children

        if pid:
            try:
                proc = psutil.Process(pid)
                return {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'status': proc.status(),
                    'children': get_children(pid)
                }
            except psutil.NoSuchProcess:
                return {}
        else:
            # Obtener procesos raíz (ppid = 1 en Unix, típicamente)
            root_processes = []
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'status']):
                try:
                    if proc.ppid() <= 1:
                        root_processes.append({
                            'pid': proc.pid,
                            'name': proc.name(),
                            'status': proc.status(),
                            'children': get_children(proc.pid)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return {'processes': root_processes}
