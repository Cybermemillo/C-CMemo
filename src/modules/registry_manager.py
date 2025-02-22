"""
Módulo para gestionar el registro de Windows.
Proporciona funciones para leer, escribir y manipular el registro de Windows de forma segura.
"""

import winreg
import logging
import json

def read_registry_key(hive_name, key_path, value_name=None):
    """
    Lee un valor del registro de Windows.
    
    Args:
        hive_name (str): Nombre del hive (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.)
        key_path (str): Ruta de la clave
        value_name (str): Nombre del valor a leer (None para valor por defecto)
    
    Returns:
        dict: Resultado de la operación con los datos leídos
    """
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }
    
    try:
        hive = hive_map.get(hive_name.upper())
        if not hive:
            return {"success": False, "error": f"Hive no válido: {hive_name}"}
            
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        if value_name is None:
            # Leer todos los valores
            values = {}
            try:
                i = 0
                while True:
                    name, data, type = winreg.EnumValue(key, i)
                    values[name] = {"data": data, "type": type}
                    i += 1
            except WindowsError:
                pass
            return {"success": True, "values": values}
        else:
            # Leer valor específico
            data, type = winreg.QueryValueEx(key, value_name)
            return {"success": True, "data": data, "type": type}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            key.Close()
        except:
            pass

def write_registry_key(hive_name, key_path, value_name, value_data, value_type="REG_SZ"):
    """
    Escribe un valor en el registro de Windows.
    
    Args:
        hive_name (str): Nombre del hive
        key_path (str): Ruta de la clave
        value_name (str): Nombre del valor
        value_data: Datos a escribir
        value_type (str): Tipo de valor (REG_SZ, REG_DWORD, etc.)
    
    Returns:
        dict: Resultado de la operación
    """
    type_map = {
        "REG_SZ": winreg.REG_SZ,
        "REG_DWORD": winreg.REG_DWORD,
        "REG_BINARY": winreg.REG_BINARY,
        "REG_MULTI_SZ": winreg.REG_MULTI_SZ
    }
    
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }
    
    try:
        hive = hive_map.get(hive_name.upper())
        if not hive:
            return {"success": False, "error": f"Hive no válido: {hive_name}"}
            
        reg_type = type_map.get(value_type.upper())
        if not reg_type:
            return {"success": False, "error": f"Tipo de registro no válido: {value_type}"}
            
        key = winreg.CreateKey(hive, key_path)
        winreg.SetValueEx(key, value_name, 0, reg_type, value_data)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            key.Close()
        except:
            pass

def delete_registry_key(hive_name, key_path, value_name=None):
    """
    Elimina una clave o valor del registro.
    
    Args:
        hive_name (str): Nombre del hive
        key_path (str): Ruta de la clave
        value_name (str): Nombre del valor a eliminar (None para eliminar la clave completa)
    
    Returns:
        dict: Resultado de la operación
    """
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }
    
    try:
        hive = hive_map.get(hive_name.upper())
        if not hive:
            return {"success": False, "error": f"Hive no válido: {hive_name}"}
            
        if value_name:
            # Eliminar valor específico
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_WRITE)
            winreg.DeleteValue(key, value_name)
        else:
            # Eliminar clave completa
            winreg.DeleteKey(hive, key_path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            key.Close()
        except:
            pass

def enum_registry_keys(hive_name, key_path):
    """
    Enumera todas las subclaves de una clave del registro.
    
    Args:
        hive_name (str): Nombre del hive
        key_path (str): Ruta de la clave
    
    Returns:
        dict: Lista de subclaves encontradas
    """
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }
    
    try:
        hive = hive_map.get(hive_name.upper())
        if not hive:
            return {"success": False, "error": f"Hive no válido: {hive_name}"}
            
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        subkeys = []
        try:
            i = 0
            while True:
                subkey = winreg.EnumKey(key, i)
                subkeys.append(subkey)
                i += 1
        except WindowsError:
            pass
        return {"success": True, "subkeys": subkeys}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            key.Close()
        except:
            pass
