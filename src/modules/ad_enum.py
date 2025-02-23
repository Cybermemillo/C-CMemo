"""
Módulo de enumeración de Active Directory.
Permite obtener información sobre usuarios, grupos y equipos en un dominio.
"""

import socket
import logging
from typing import Dict, List, Union, Optional
import json
from datetime import datetime

try:
    import ldap3
    LDAP_SUPPORT = True
except ImportError:
    LDAP_SUPPORT = False
    logging.warning("Módulo ldap3 no encontrado. La enumeración de AD estará deshabilitada.")

try:
    import dns.resolver
    DNS_SUPPORT = True
except ImportError:
    DNS_SUPPORT = False
    logging.warning("Módulo dns.resolver no encontrado. La resolución DNS estará limitada.")

class ADEnumerator:
    def __init__(self):
        """Inicializa el enumerador de Active Directory."""
        if not LDAP_SUPPORT:
            raise ImportError("El módulo ldap3 es requerido para usar ADEnumerator")
        if not DNS_SUPPORT:
            raise ImportError("El módulo dns.resolver es requerido para usar ADEnumerator")
            
        self.server = None
        self.connection = None
        self.domain = None
        self.base_dn = None

    def connect(self, domain: str, username: str = None, password: str = None) -> Dict[str, Union[bool, str]]:
        """
        Conecta al dominio de Active Directory.
        
        Args:
            domain: Nombre del dominio
            username: Usuario con acceso al dominio (opcional)
            password: Contraseña del usuario (opcional)
            
        Returns:
            Dict indicando éxito o error
        """
        try:
            # Resolver controlador de dominio
            resolver = dns.resolver.Resolver()
            records = resolver.resolve(f"_ldap._tcp.{domain}", 'SRV')
            if not records:
                return {"success": False, "error": "No se encontraron DCs"}
                
            # Obtener DC con mayor prioridad
            dc_host = str(records[0].target).rstrip('.')
            self.domain = domain
            self.base_dn = ','.join([f"DC={x}" for x in domain.split('.')])
            
            # Conectar al DC
            self.server = ldap3.Server(
                dc_host,
                get_info=ldap3.ALL,
                use_ssl=True
            )
            
            if username and password:
                # Autenticación con credenciales
                self.connection = ldap3.Connection(
                    self.server,
                    user=f"{username}@{domain}",
                    password=password,
                    authentication=ldap3.NTLM
                )
            else:
                # Conexión anónima
                self.connection = ldap3.Connection(self.server)
            
            if not self.connection.bind():
                return {
                    "success": False,
                    "error": f"Error de autenticación: {self.connection.result}"
                }
                
            return {"success": True}
            
        except Exception as e:
            logging.error(f"Error conectando a AD: {e}")
            return {"success": False, "error": str(e)}

    def enum_users(self, limit: int = 100) -> Dict[str, Union[bool, List[Dict[str, str]], str]]:
        """
        Enumera usuarios del dominio.
        
        Args:
            limit: Límite de usuarios a retornar
            
        Returns:
            Dict con lista de usuarios o error
        """
        try:
            if not self.connection:
                return {"success": False, "error": "No hay conexión al dominio"}
                
            self.connection.search(
                self.base_dn,
                '(&(objectClass=user)(objectCategory=person))',
                attributes=[
                    'sAMAccountName',
                    'mail',
                    'userAccountControl',
                    'memberOf',
                    'whenCreated',
                    'lastLogon'
                ],
                size_limit=limit
            )
            
            users = []
            for entry in self.connection.entries:
                user = {
                    "username": entry.sAMAccountName.value,
                    "email": entry.mail.value if entry.mail else None,
                    "enabled": not bool(entry.userAccountControl.value & 2),
                    "groups": [str(g).split(',')[0].split('=')[1] for g in entry.memberOf],
                    "created": str(entry.whenCreated.value) if entry.whenCreated else None,
                    "last_logon": datetime.fromtimestamp(entry.lastLogon.value / 10000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S') if entry.lastLogon.value else None
                }
                users.append(user)
                
            return {
                "success": True,
                "users": users
            }
            
        except Exception as e:
            logging.error(f"Error enumerando usuarios: {e}")
            return {"success": False, "error": str(e)}

    def enum_groups(self) -> Dict[str, Union[bool, List[Dict[str, str]], str]]:
        """
        Enumera grupos del dominio.
        
        Returns:
            Dict con lista de grupos o error
        """
        try:
            if not self.connection:
                return {"success": False, "error": "No hay conexión al dominio"}
                
            self.connection.search(
                self.base_dn,
                '(objectClass=group)',
                attributes=[
                    'cn',
                    'description',
                    'member',
                    'groupType'
                ]
            )
            
            groups = []
            for entry in self.connection.entries:
                group = {
                    "name": entry.cn.value,
                    "description": entry.description.value if entry.description else None,
                    "members": len(entry.member) if entry.member else 0,
                    "type": "Security" if entry.groupType.value & 0x80000000 else "Distribution"
                }
                groups.append(group)
                
            return {
                "success": True,
                "groups": groups
            }
            
        except Exception as e:
            logging.error(f"Error enumerando grupos: {e}")
            return {"success": False, "error": str(e)}

    def enum_computers(self) -> Dict[str, Union[bool, List[Dict[str, str]], str]]:
        """
        Enumera equipos del dominio.
        
        Returns:
            Dict con lista de equipos o error
        """
        try:
            if not self.connection:
                return {"success": False, "error": "No hay conexión al dominio"}
                
            self.connection.search(
                self.base_dn,
                '(objectClass=computer)',
                attributes=[
                    'dNSHostName',
                    'operatingSystem',
                    'operatingSystemVersion',
                    'lastLogon',
                    'logonCount'
                ]
            )
            
            computers = []
            for entry in self.connection.entries:
                computer = {
                    "hostname": entry.dNSHostName.value if entry.dNSHostName else None,
                    "os": entry.operatingSystem.value if entry.operatingSystem else None,
                    "version": entry.operatingSystemVersion.value if entry.operatingSystemVersion else None,
                    "last_logon": datetime.fromtimestamp(entry.lastLogon.value / 10000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S') if entry.lastLogon.value else None,
                    "logon_count": entry.logonCount.value if entry.logonCount else 0
                }
                computers.append(computer)
                
            return {
                "success": True,
                "computers": computers
            }
            
        except Exception as e:
            logging.error(f"Error enumerando equipos: {e}")
            return {"success": False, "error": str(e)}

    def get_domain_admins(self) -> Dict[str, Union[bool, List[str], str]]:
        """
        Obtiene lista de administradores del dominio.
        
        Returns:
            Dict con lista de administradores o error
        """
        try:
            if not self.connection:
                return {"success": False, "error": "No hay conexión al dominio"}
                
            self.connection.search(
                self.base_dn,
                '(&(objectClass=group)(cn=Domain Admins))',
                attributes=['member']
            )
            
            if not self.connection.entries:
                return {"success": False, "error": "Grupo Domain Admins no encontrado"}
                
            admins = []
            for member_dn in self.connection.entries[0].member:
                self.connection.search(
                    member_dn,
                    '(objectClass=*)',
                    attributes=['sAMAccountName']
                )
                if self.connection.entries:
                    admins.append(self.connection.entries[0].sAMAccountName.value)
                    
            return {
                "success": True,
                "admins": admins
            }
            
        except Exception as e:
            logging.error(f"Error obteniendo administradores: {e}")
            return {"success": False, "error": str(e)}

    def get_user_info(self, username: str) -> Dict[str, Union[bool, Dict[str, str], str]]:
        """
        Obtiene información detallada de un usuario.
        
        Args:
            username: Nombre del usuario
            
        Returns:
            Dict con información del usuario o error
        """
        try:
            if not self.connection:
                return {"success": False, "error": "No hay conexión al dominio"}
                
            self.connection.search(
                self.base_dn,
                f'(&(objectClass=user)(sAMAccountName={username}))',
                attributes=[
                    'displayName',
                    'mail',
                    'userAccountControl',
                    'memberOf',
                    'whenCreated',
                    'lastLogon',
                    'pwdLastSet',
                    'logonCount',
                    'badPwdCount'
                ]
            )
            
            if not self.connection.entries:
                return {"success": False, "error": "Usuario no encontrado"}
                
            entry = self.connection.entries[0]
            info = {
                "display_name": entry.displayName.value if entry.displayName else None,
                "email": entry.mail.value if entry.mail else None,
                "enabled": not bool(entry.userAccountControl.value & 2),
                "groups": [str(g).split(',')[0].split('=')[1] for g in entry.memberOf],
                "created": str(entry.whenCreated.value) if entry.whenCreated else None,
                "last_logon": datetime.fromtimestamp(entry.lastLogon.value / 10000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S') if entry.lastLogon.value else None,
                "password_last_set": datetime.fromtimestamp(entry.pwdLastSet.value / 10000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S') if entry.pwdLastSet.value else None,
                "logon_count": entry.logonCount.value if entry.logonCount else 0,
                "bad_password_count": entry.badPwdCount.value if entry.badPwdCount else 0
            }
            
            return {
                "success": True,
                "info": info
            }
            
        except Exception as e:
            logging.error(f"Error obteniendo información de usuario: {e}")
            return {"success": False, "error": str(e)}

    def disconnect(self):
        """Cierra la conexión con el dominio."""
        try:
            if self.connection:
                self.connection.unbind()
            self.connection = None
            self.server = None
        except Exception as e:
            logging.error(f"Error desconectando de AD: {e}")

"""
Módulo para enumeración de Active Directory
"""

class ADEnum:
    def __init__(self):
        self.domain = None
        
    def enumerate_users(self):
        """Enumera usuarios del dominio"""
        pass
        
    def enumerate_groups(self):
        """Enumera grupos del dominio"""
        pass
        
    def enumerate_computers(self):
        """Enumera computadoras del dominio"""
        pass
