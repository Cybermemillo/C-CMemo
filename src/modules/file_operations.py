"""
Módulo de operaciones con archivos.
Proporciona funciones para manipular archivos y directorios de forma segura.
"""

import os
import shutil
import base64
import logging
from typing import Dict, List, Union, Optional
import stat
import platform
from pathlib import Path

def list_directory(path: str) -> Dict[str, Union[List[str], str, bool]]:
    """
    Lista el contenido de un directorio.
    
    Args:
        path: Ruta del directorio a listar
        
    Returns:
        Dict con la lista de archivos, permisos y metadata
    """
    try:
        # Normalizar y validar la ruta
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return {"success": False, "error": "La ruta no existe"}
            
        # Listar contenido
        items = []
        for item in os.scandir(path):
            try:
                stat_info = item.stat()
                item_info = {
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size": stat_info.st_size,
                    "modified": stat_info.st_mtime,
                    "permissions": stat.filemode(stat_info.st_mode),
                    "owner": stat_info.st_uid,
                    "group": stat_info.st_gid
                }
                items.append(item_info)
            except Exception as e:
                logging.warning(f"Error al obtener información de {item.path}: {e}")
                continue

        return {
            "success": True,
            "path": path,
            "items": items,
            "total_items": len(items),
            "system": platform.system()
        }
        
    except Exception as e:
        logging.error(f"Error listando directorio {path}: {e}")
        return {"success": False, "error": str(e)}

def download_file(path: str) -> Dict[str, Union[str, bool]]:
    """
    Lee un archivo y lo devuelve en formato base64.
    
    Args:
        path: Ruta del archivo a descargar
        
    Returns:
        Dict con el contenido del archivo en base64
    """
    try:
        path = os.path.abspath(path)
        if not os.path.exists(path) or not os.path.isfile(path):
            return {"success": False, "error": "El archivo no existe"}
            
        # Verificar tamaño
        if os.path.getsize(path) > 50_000_000:  # 50MB límite
            return {"success": False, "error": "Archivo demasiado grande"}
            
        with open(path, 'rb') as f:
            content = base64.b64encode(f.read()).decode('utf-8')
            return {
                "success": True,
                "filename": os.path.basename(path),
                "content": content,
                "size": os.path.getsize(path)
            }
            
    except Exception as e:
        logging.error(f"Error descargando archivo {path}: {e}")
        return {"success": False, "error": str(e)}

def upload_file(path: str, content: str) -> Dict[str, bool]:
    """
    Guarda un archivo desde contenido base64.
    
    Args:
        path: Ruta donde guardar el archivo
        content: Contenido del archivo en base64
        
    Returns:
        Dict indicando éxito o fracaso
    """
    try:
        path = os.path.abspath(path)
        
        # Verificar directorio padre
        parent_dir = os.path.dirname(path)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
            
        # Decodificar y guardar
        file_content = base64.b64decode(content)
        with open(path, 'wb') as f:
            f.write(file_content)
            
        return {"success": True}
        
    except Exception as e:
        logging.error(f"Error subiendo archivo a {path}: {e}")
        return {"success": False, "error": str(e)}

def delete_file(path: str) -> Dict[str, bool]:
    """
    Elimina un archivo o directorio.
    
    Args:
        path: Ruta del archivo/directorio a eliminar
        
    Returns:
        Dict indicando éxito o fracaso
    """
    try:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return {"success": False, "error": "La ruta no existe"}
            
        if os.path.isfile(path):
            os.remove(path)
        else:
            shutil.rmtree(path)
            
        return {"success": True}
        
    except Exception as e:
        logging.error(f"Error eliminando {path}: {e}")
        return {"success": False, "error": str(e)}

def create_directory(path: str) -> Dict[str, bool]:
    """
    Crea un nuevo directorio.
    
    Args:
        path: Ruta del directorio a crear
        
    Returns:
        Dict indicando éxito o fracaso
    """
    try:
        path = os.path.abspath(path)
        os.makedirs(path, exist_ok=True)
        return {"success": True}
        
    except Exception as e:
        logging.error(f"Error creando directorio {path}: {e}")
        return {"success": False, "error": str(e)}

def check_write_permission(path: str) -> bool:
    """
    Verifica si se tiene permiso de escritura en una ruta.
    
    Args:
        path: Ruta a verificar
        
    Returns:
        bool indicando si hay permiso de escritura
    """
    try:
        path = os.path.abspath(path)
        return os.access(path, os.W_OK)
    except Exception as e:
        logging.error(f"Error verificando permisos en {path}: {e}")
        return False

def get_file_info(path: str) -> Dict[str, Union[str, int, bool]]:
    """
    Obtiene información detallada de un archivo.
    
    Args:
        path: Ruta del archivo
        
    Returns:
        Dict con metadatos del archivo
    """
    try:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return {"success": False, "error": "La ruta no existe"}
            
        stat_info = os.stat(path)
        return {
            "success": True,
            "name": os.path.basename(path),
            "size": stat_info.st_size,
            "created": stat_info.st_ctime,
            "modified": stat_info.st_mtime,
            "accessed": stat_info.st_atime,
            "permissions": stat.filemode(stat_info.st_mode),
            "is_dir": os.path.isdir(path),
            "owner": stat_info.st_uid,
            "group": stat_info.st_gid
        }
        
    except Exception as e:
        logging.error(f"Error obteniendo información de {path}: {e}")
        return {"success": False, "error": str(e)}
