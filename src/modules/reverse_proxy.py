"""
Módulo de proxy reverso.
Permite redirigir tráfico a través del bot para ocultar la comunicación.
"""

import socket
import threading
import select
import logging
import sys
import queue
import time
from typing import Dict, Set, Optional, Tuple, List
import ssl
import base64
import http.client
from urllib.parse import urlparse

class ReverseProxy:
    def __init__(self, local_host: str = "127.0.0.1", local_port: int = 8080):
        """
        Inicializa el proxy reverso.
        
        Args:
            local_host: Host local donde escuchar
            local_port: Puerto local donde escuchar
        """
        self.local_host = local_host
        self.local_port = local_port
        self.running = False
        self.connections: Dict[socket.socket, socket.socket] = {}
        self.routes: Dict[Tuple[str, int], Tuple[str, int]] = {}
        self.lock = threading.Lock()
        self.bufsize = 4096
        self.active_tunnels: Set[Tuple[str, int]] = set()

    def add_route(self, local_port: int, remote_host: str, remote_port: int) -> bool:
        """
        Añade una nueva ruta de redirección.
        
        Args:
            local_port: Puerto local a escuchar
            remote_host: Host remoto destino
            remote_port: Puerto remoto destino
            
        Returns:
            bool indicando si se añadió la ruta correctamente
        """
        try:
            self.routes[(self.local_host, local_port)] = (remote_host, remote_port)
            return True
        except Exception as e:
            logging.error(f"Error añadiendo ruta: {e}")
            return False

    def remove_route(self, local_port: int) -> bool:
        """
        Elimina una ruta de redirección.
        
        Args:
            local_port: Puerto local de la ruta a eliminar
            
        Returns:
            bool indicando si se eliminó la ruta
        """
        try:
            del self.routes[(self.local_host, local_port)]
            return True
        except KeyError:
            return False

    def start(self) -> bool:
        """
        Inicia el proxy reverso.
        
        Returns:
            bool indicando si se inició correctamente
        """
        if self.running:
            return False

        self.running = True
        
        for local_endpoint in self.routes.keys():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(local_endpoint)
                server.listen(5)
                
                thread = threading.Thread(
                    target=self._handle_incoming,
                    args=(server, self.routes[local_endpoint]),
                    daemon=True
                )
                thread.start()
                
                logging.info(f"Proxy escuchando en {local_endpoint}")
                
            except Exception as e:
                logging.error(f"Error iniciando proxy en {local_endpoint}: {e}")
                self.running = False
                return False

        return True

    def stop(self):
        """Detiene el proxy reverso."""
        self.running = False
        with self.lock:
            for local_sock, remote_sock in self.connections.items():
                try:
                    local_sock.close()
                    remote_sock.close()
                except:
                    pass
            self.connections.clear()
            self.active_tunnels.clear()

    def _handle_incoming(self, server: socket.socket, remote_endpoint: Tuple[str, int]):
        """Maneja conexiones entrantes."""
        while self.running:
            try:
                local_socket, addr = server.accept()
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect(remote_endpoint)
                
                with self.lock:
                    self.connections[local_socket] = remote_socket
                    self.active_tunnels.add(remote_endpoint)
                
                threading.Thread(
                    target=self._handle_tunnel,
                    args=(local_socket, remote_socket),
                    daemon=True
                ).start()
                
                logging.info(f"Nuevo túnel: {addr} -> {remote_endpoint}")
                
            except Exception as e:
                logging.error(f"Error en conexión entrante: {e}")
                continue

    def _handle_tunnel(self, local_socket: socket.socket, remote_socket: socket.socket):
        """Maneja un túnel individual entre cliente y servidor."""
        while self.running:
            try:
                readable, _, exceptional = select.select(
                    [local_socket, remote_socket],
                    [],
                    [local_socket, remote_socket],
                    1.0
                )
                
                if exceptional:
                    break
                    
                for sock in readable:
                    other = remote_socket if sock is local_socket else local_socket
                    data = sock.recv(self.bufsize)
                    
                    if not data:
                        return
                        
                    other.send(data)
                    
            except Exception as e:
                logging.error(f"Error en túnel: {e}")
                break
                
        self._cleanup_tunnel(local_socket, remote_socket)

    def _cleanup_tunnel(self, local_socket: socket.socket, remote_socket: socket.socket):
        """Limpia las conexiones cuando un túnel se cierra."""
        with self.lock:
            if local_socket in self.connections:
                remote_endpoint = remote_socket.getpeername()
                del self.connections[local_socket]
                self.active_tunnels.discard(remote_endpoint)
                
        try:
            local_socket.close()
            remote_socket.close()
        except:
            pass

    def get_active_tunnels(self) -> Set[Tuple[str, int]]:
        """
        Obtiene los túneles activos.
        
        Returns:
            Set con las tuplas (host, puerto) de los túneles activos
        """
        with self.lock:
            return self.active_tunnels.copy()

    def get_statistics(self) -> Dict[str, int]:
        """
        Obtiene estadísticas del proxy.
        
        Returns:
            Dict con estadísticas básicas
        """
        with self.lock:
            return {
                "active_connections": len(self.connections),
                "active_tunnels": len(self.active_tunnels),
                "configured_routes": len(self.routes)
            }

    def create_https_tunnel(self, local_port: int, remote_host: str, remote_port: int = 443) -> bool:
        """
        Crea un túnel HTTPS.
        
        Args:
            local_port: Puerto local para el túnel
            remote_host: Host remoto
            remote_port: Puerto remoto (443 por defecto)
            
        Returns:
            bool indicando si se creó el túnel
        """
        try:
            # Configurar contexto SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            def handle_https_tunnel(local_socket: socket.socket, addr: Tuple[str, int]):
                try:
                    # Conectar al servidor remoto usando SSL
                    remote_socket = context.wrap_socket(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                        server_hostname=remote_host
                    )
                    remote_socket.connect((remote_host, remote_port))
                    
                    # Manejar el túnel
                    self._handle_tunnel(local_socket, remote_socket)
                    
                except Exception as e:
                    logging.error(f"Error en túnel HTTPS: {e}")
                finally:
                    self._cleanup_tunnel(local_socket, remote_socket)
            
            # Crear socket de escucha
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.local_host, local_port))
            server.listen(5)
            
            # Agregar la ruta
            self.routes[(self.local_host, local_port)] = (remote_host, remote_port)
            
            # Iniciar thread para aceptar conexiones
            threading.Thread(
                target=lambda: self._accept_https_connections(server, handle_https_tunnel),
                daemon=True
            ).start()
            
            return True
            
        except Exception as e:
            logging.error(f"Error creando túnel HTTPS: {e}")
            return False

    def _accept_https_connections(self, server: socket.socket, handler):
        """Acepta conexiones para el túnel HTTPS."""
        while self.running:
            try:
                client_socket, addr = server.accept()
                threading.Thread(target=handler, args=(client_socket, addr)).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Error aceptando conexión HTTPS: {e}")

    def create_socks_proxy(self, local_port: int) -> bool:
        """
        Crea un proxy SOCKS5.
        
        Args:
            local_port: Puerto local para el proxy
            
        Returns:
            bool indicando si se creó el proxy
        """
        try:
            def handle_socks_client(client: socket.socket):
                try:
                    # Autenticación SOCKS5
                    version = client.recv(1)
                    if version != b'\x05':
                        return
                        
                    nmethods = client.recv(1)[0]
                    methods = client.recv(nmethods)
                    
                    # Responder sin autenticación
                    client.send(b'\x05\x00')
                    
                    # Recibir petición
                    version = client.recv(1)
                    if version != b'\x05':
                        return
                        
                    cmd = client.recv(1)[0]
                    _ = client.recv(1)  # Reserved
                    atyp = client.recv(1)[0]
                    
                    if cmd != 1:  # Solo soportamos CONNECT
                        client.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                        return
                        
                    # Obtener dirección destino
                    if atyp == 1:  # IPv4
                        addr = socket.inet_ntoa(client.recv(4))
                        port = int.from_bytes(client.recv(2), 'big')
                    elif atyp == 3:  # Domain
                        length = client.recv(1)[0]
                        addr = client.recv(length).decode()
                        port = int.from_bytes(client.recv(2), 'big')
                    else:
                        client.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                        return
                        
                    # Conectar al destino
                    try:
                        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        remote.connect((addr, port))
                        bind_addr = remote.getsockname()
                        
                        # Responder éxito
                        response = b'\x05\x00\x00\x01'
                        response += socket.inet_aton(bind_addr[0])
                        response += bind_addr[1].to_bytes(2, 'big')
                        client.send(response)
                        
                    except:
                        client.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                        return
                        
                    # Manejar el túnel
                    self._handle_tunnel(client, remote)
                    
                except Exception as e:
                    logging.error(f"Error en cliente SOCKS: {e}")
                finally:
                    try:
                        client.close()
                    except:
                        pass
            
            # Crear socket SOCKS
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.local_host, local_port))
            server.listen(5)
            
            # Agregar la ruta
            self.routes[(self.local_host, local_port)] = ("SOCKS5", 0)
            
            # Iniciar thread para aceptar conexiones
            threading.Thread(
                target=lambda: self._accept_socks_connections(server, handle_socks_client),
                daemon=True
            ).start()
            
            return True
            
        except Exception as e:
            logging.error(f"Error creando proxy SOCKS: {e}")
            return False

    def _accept_socks_connections(self, server: socket.socket, handler):
        """Acepta conexiones para el proxy SOCKS."""
        while self.running:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handler, args=(client_socket,)).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Error aceptando conexión SOCKS: {e}")

    def create_http_proxy(self, local_port: int) -> bool:
        """
        Crea un proxy HTTP.
        
        Args:
            local_port: Puerto local para el proxy
            
        Returns:
            bool indicando si se creó el proxy
        """
        try:
            def handle_http_client(client: socket.socket):
                try:
                    # Recibir petición HTTP
                    data = client.recv(8192)
                    first_line = data.split(b'\n')[0]
                    method, url, _ = first_line.split(b' ')
                    
                    # Parsear URL
                    url = url.decode()
                    parsed = urlparse(url)
                    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                    
                    if method == b'CONNECT':
                        # Petición HTTPS
                        hostname = parsed.path
                        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        remote.connect((hostname, port))
                        client.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
                        self._handle_tunnel(client, remote)
                    else:
                        # Petición HTTP
                        conn = http.client.HTTPConnection(parsed.hostname, port)
                        path = parsed.path or '/'
                        if parsed.query:
                            path += '?' + parsed.query
                            
                        # Reenviar headers
                        headers = {}
                        for line in data.split(b'\n')[1:]:
                            line = line.strip()
                            if not line:
                                break
                            key, value = line.split(b': ', 1)
                            headers[key.decode()] = value.decode()
                            
                        # Hacer petición
                        conn.request(method.decode(), path, headers=headers)
                        response = conn.getresponse()
                        
                        # Reenviar respuesta
                        client.send(f'HTTP/1.1 {response.status} {response.reason}\r\n'.encode())
                        for header, value in response.getheaders():
                            client.send(f'{header}: {value}\r\n'.encode())
                        client.send(b'\r\n')
                        
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            client.send(chunk)
                            
                except Exception as e:
                    logging.error(f"Error en cliente HTTP: {e}")
                finally:
                    try:
                        client.close()
                    except:
                        pass
            
            # Crear socket HTTP
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.local_host, local_port))
            server.listen(5)
            
            # Agregar la ruta
            self.routes[(self.local_host, local_port)] = ("HTTP", 0)
            
            # Iniciar thread para aceptar conexiones
            threading.Thread(
                target=lambda: self._accept_http_connections(server, handle_http_client),
                daemon=True
            ).start()
            
            return True
            
        except Exception as e:
            logging.error(f"Error creando proxy HTTP: {e}")
            return False

    def _accept_http_connections(self, server: socket.socket, handler):
        """Acepta conexiones para el proxy HTTP."""
        while self.running:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handler, args=(client_socket,)).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Error aceptando conexión HTTP: {e}")
