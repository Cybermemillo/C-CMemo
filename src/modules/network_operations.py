"""
Módulo de operaciones de red.
Proporciona funciones para enumerar y analizar conexiones de red,
interfaces y realizar operaciones básicas de networking.
"""

import psutil
import socket
import subprocess
import platform
import logging
import struct
import requests
from typing import Dict, List, Optional, Union, Tuple
from ipaddress import IPv4Network, IPv4Address

class NetworkAnalyzer:
    def __init__(self):
        """Inicializa el analizador de red."""
        self.os_type = platform.system().lower()

    def get_network_interfaces(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Obtiene información detallada de todas las interfaces de red usando psutil.
        
        Returns:
            Lista de diccionarios con información de cada interfaz
        """
        try:
            interfaces = []
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for iface, addrs in net_if_addrs.items():
                try:
                    ipv4_addresses = []
                    ipv4_netmasks = []
                    ipv6_addresses = []
                    mac = 'Unknown'
                    
                    for addr in addrs:
                        if addr.family == socket.AF_INET:  # IPv4
                            ipv4_addresses.append(addr.address)
                            if hasattr(addr, 'netmask'):
                                ipv4_netmasks.append(addr.netmask)
                        elif addr.family == socket.AF_INET6:  # IPv6
                            ipv6_addresses.append(addr.address)
                        elif addr.family == psutil.AF_LINK:  # MAC
                            mac = addr.address
                    
                    stats = net_if_stats.get(iface, None)
                    interface_info = {
                        'name': iface,
                        'mac': mac,
                        'ipv4_addresses': ipv4_addresses,
                        'ipv4_netmasks': ipv4_netmasks,
                        'ipv6_addresses': ipv6_addresses,
                        'status': 'up' if stats and stats.isup else 'down',
                        'mtu': stats.mtu if stats else None
                    }
                    interfaces.append(interface_info)
                except Exception as e:
                    logging.error(f"Error obteniendo información de interfaz {iface}: {e}")
                    continue
                    
            return interfaces
        except Exception as e:
            logging.error(f"Error listando interfaces de red: {e}")
            return []

    def get_active_connections(self) -> List[Dict[str, Union[str, int]]]:
        """
        Lista todas las conexiones de red activas.
        
        Returns:
            Lista de diccionarios con información de cada conexión
        """
        try:
            connections = []
            for conn in psutil.net_connections(kind='all'):
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    connection_info = {
                        'protocol': self._get_protocol_name(conn.type),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': process.name() if process else "Unknown",
                        'user': process.username() if process else "Unknown"
                    }
                    connections.append(connection_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return connections
        except Exception as e:
            logging.error(f"Error obteniendo conexiones activas: {e}")
            return []

    def scan_local_network(self, interface: str = None) -> List[Dict[str, str]]:
        """
        Realiza un escaneo básico de la red local.
        
        Args:
            interface: Nombre de la interfaz a escanear (opcional)
            
        Returns:
            Lista de dispositivos encontrados
        """
        try:
            if not interface:
                interface = self._get_default_interface()

            network = self._get_network_range(interface)
            if not network:
                return []

            devices = []
            for ip in network.hosts():
                try:
                    if self._ping_host(str(ip)):
                        hostname = socket.getfqdn(str(ip))
                        mac = self._get_mac_address(str(ip))
                        devices.append({
                            'ip': str(ip),
                            'hostname': hostname,
                            'mac': mac,
                            'vendor': self._get_vendor_from_mac(mac)
                        })
                except Exception as e:
                    logging.debug(f"Error escaneando {ip}: {e}")
                    continue

            return devices
        except Exception as e:
            logging.error(f"Error escaneando red local: {e}")
            return []

    def get_network_statistics(self) -> Dict[str, Dict[str, int]]:
        """
        Obtiene estadísticas de uso de red por interfaz.
        
        Returns:
            Diccionario con estadísticas por interfaz
        """
        try:
            stats = {}
            net_io = psutil.net_io_counters(pernic=True)
            
            for iface, counters in net_io.items():
                stats[iface] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout
                }
            
            return stats
        except Exception as e:
            logging.error(f"Error obteniendo estadísticas de red: {e}")
            return {}

    def analyze_dns(self, domain: str) -> Dict[str, Union[List[str], str]]:
        """
        Realiza un análisis básico de DNS para un dominio.
        
        Args:
            domain: Dominio a analizar
            
        Returns:
            Diccionario con información DNS
        """
        try:
            result = {
                'domain': domain,
                'a_records': [],
                'mx_records': [],
                'ns_records': [],
                'txt_records': []
            }
            
            # Registros A
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                result['a_records'] = ips
            except:
                pass
                
            # Otros registros mediante dig/nslookup
            if self.os_type == "linux":
                cmd = f"dig {domain} ANY +noall +answer"
            else:
                cmd = f"nslookup -type=any {domain}"
                
            try:
                output = subprocess.check_output(cmd, shell=True, text=True)
                # Parsear salida según el formato del comando
                # Este es un parsing básico, se puede mejorar según necesidades
                for line in output.splitlines():
                    if "MX" in line:
                        result['mx_records'].append(line.strip())
                    elif "NS" in line:
                        result['ns_records'].append(line.strip())
                    elif "TXT" in line:
                        result['txt_records'].append(line.strip())
            except:
                pass
                
            return result
        except Exception as e:
            logging.error(f"Error analizando DNS para {domain}: {e}")
            return {'error': str(e)}

    def _get_default_interface(self) -> Optional[str]:
        """Obtiene la interfaz de red predeterminada usando psutil."""
        try:
            # Obtener la interfaz con conexión activa
            stats = psutil.net_if_stats()
            for iface, stat in stats.items():
                if stat.isup and self._has_internet_connection(iface):
                    return iface
        except:
            pass
        return None

    def _has_internet_connection(self, iface: str) -> bool:
        """Verifica si una interfaz tiene conexión a Internet."""
        try:
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return True
        except:
            pass
        return False

    def _get_network_range(self, interface: str) -> Optional[IPv4Network]:
        """Obtiene el rango de red para una interfaz usando psutil."""
        try:
            addrs = psutil.net_if_addrs().get(interface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    if ip and netmask:
                        network = IPv4Network(f"{ip}/{netmask}", strict=False)
                        return network
        except:
            pass
        return None

    def _ping_host(self, ip: str) -> bool:
        """Realiza un ping a una IP."""
        try:
            if self.os_type == "windows":
                cmd = f"ping -n 1 -w 100 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"
            return subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False

    def _get_mac_address(self, ip: str) -> str:
        """Obtiene la dirección MAC de una IP."""
        try:
            if self.os_type == "linux":
                cmd = f"arp -n {ip}"
            else:
                cmd = f"arp -a {ip}"
            output = subprocess.check_output(cmd, shell=True).decode()
            # Extraer MAC del output (el formato varía según el SO)
            # Este es un parsing básico, se puede mejorar
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part or "-" in part:
                            return part
        except:
            pass
        return "Unknown"

    def _get_vendor_from_mac(self, mac: str) -> str:
        """Obtiene el fabricante a partir de una dirección MAC."""
        try:
            if mac and mac != "Unknown":
                # Usar los primeros 6 caracteres (OUI)
                oui = mac.replace(":", "").replace("-", "")[:6].upper()
                # Se podría implementar una base de datos local de OUIs
                # o hacer una consulta a una API de búsqueda de fabricantes
                return "Vendor lookup not implemented"
        except:
            pass
        return "Unknown"
