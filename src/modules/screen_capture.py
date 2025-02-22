"""
Módulo de captura de pantalla en tiempo real.
Proporciona capacidades para capturar, comprimir y transmitir
el escritorio del sistema de forma eficiente.
"""

import time
import threading
import logging
import mss
import mss.tools
import cv2
import numpy as np
import base64
import io
from PIL import Image
import zlib
from queue import Queue
import socket

class ScreenCapture:
    def __init__(self, quality=60, fps=10, compression_level=6):
        """
        Inicializa el capturador de pantalla.
        
        Args:
            quality (int): Calidad de compresión JPEG (1-100)
            fps (int): Frames por segundo objetivo
            compression_level (int): Nivel de compresión zlib (1-9)
        """
        self.quality = quality
        self.fps = fps
        self.compression_level = compression_level
        self.running = False
        self.frame_queue = Queue(maxsize=30)  # Buffer para 30 frames
        self.sct = mss.mss()
        self.latest_frame = None
        self.capture_thread = None
        self.process_thread = None
        self.stream_sockets = set()
        self.lock = threading.Lock()

    def start(self):
        """Inicia la captura de pantalla."""
        try:
            self.running = True
            self.capture_thread = threading.Thread(target=self._capture_loop)
            self.process_thread = threading.Thread(target=self._process_loop)
            self.capture_thread.daemon = True
            self.process_thread.daemon = True
            self.capture_thread.start()
            self.process_thread.start()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop(self):
        """Detiene la captura de pantalla."""
        try:
            self.running = False
            if self.capture_thread:
                self.capture_thread.join()
            if self.process_thread:
                self.process_thread.join()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _capture_loop(self):
        """Loop principal de captura."""
        frame_time = 1.0 / self.fps
        while self.running:
            try:
                start_time = time.time()
                
                # Capturar pantalla
                screenshot = self.sct.grab(self.sct.monitors[0])
                
                # Convertir a formato PIL
                img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
                
                # Redimensionar si es necesario
                if img.size[0] > 1920 or img.size[1] > 1080:
                    img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
                
                # Poner en cola para procesamiento
                if not self.frame_queue.full():
                    self.frame_queue.put(img)
                
                # Mantener FPS constante
                elapsed = time.time() - start_time
                if elapsed < frame_time:
                    time.sleep(frame_time - elapsed)
                    
            except Exception as e:
                logging.error(f"Error en captura: {e}")
                time.sleep(0.1)

    def _process_loop(self):
        """Loop de procesamiento de frames."""
        while self.running:
            try:
                if not self.frame_queue.empty():
                    img = self.frame_queue.get()
                    
                    # Convertir a JPEG
                    buffer = io.BytesIO()
                    img.save(buffer, format="JPEG", quality=self.quality)
                    jpeg_data = buffer.getvalue()
                    
                    # Comprimir con zlib
                    compressed_data = zlib.compress(jpeg_data, self.compression_level)
                    
                    # Guardar el frame más reciente
                    with self.lock:
                        self.latest_frame = compressed_data
                    
                    # Enviar a clientes conectados
                    self._broadcast_frame(compressed_data)
            except Exception as e:
                logging.error(f"Error en procesamiento: {e}")
                time.sleep(0.1)

    def get_latest_frame(self, format="jpeg"):
        """
        Obtiene el último frame capturado.
        
        Args:
            format (str): Formato de salida ('jpeg', 'base64', 'compressed')
        
        Returns:
            dict: Frame en el formato especificado
        """
        try:
            with self.lock:
                if not self.latest_frame:
                    return {"success": False, "error": "No hay frames disponibles"}
                
                if format == "compressed":
                    return {
                        "success": True,
                        "data": self.latest_frame,
                        "compression": "zlib"
                    }
                
                # Descomprimir
                jpeg_data = zlib.decompress(self.latest_frame)
                
                if format == "base64":
                    return {
                        "success": True,
                        "data": base64.b64encode(jpeg_data).decode()
                    }
                else:  # jpeg
                    return {
                        "success": True,
                        "data": jpeg_data
                    }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def add_stream_socket(self, socket):
        """Añade un socket para streaming."""
        self.stream_sockets.add(socket)

    def remove_stream_socket(self, socket):
        """Elimina un socket de streaming."""
        self.stream_sockets.discard(socket)

    def _broadcast_frame(self, frame_data):
        """Envía el frame a todos los sockets conectados."""
        dead_sockets = set()
        
        for sock in self.stream_sockets:
            try:
                # Enviar tamaño del frame
                size = len(frame_data)
                sock.send(size.to_bytes(4, byteorder='big'))
                
                # Enviar frame
                sock.sendall(frame_data)
            except:
                dead_sockets.add(sock)
        
        # Limpiar sockets muertos
        for sock in dead_sockets:
            self.remove_stream_socket(sock)

    def get_stats(self):
        """Obtiene estadísticas de la captura."""
        try:
            return {
                "success": True,
                "stats": {
                    "fps": self.fps,
                    "quality": self.quality,
                    "compression": self.compression_level,
                    "queue_size": self.frame_queue.qsize(),
                    "clients": len(self.stream_sockets),
                    "resolution": self.sct.monitors[0]["width"] + "x" + self.sct.monitors[0]["height"]
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def cambiar_configuracion(self, **kwargs):
        """
        Actualiza la configuración en tiempo real.
        
        Args:
            **kwargs: Parámetros a actualizar (quality, fps, compression_level)
        """
        try:
            if "quality" in kwargs:
                self.quality = max(1, min(100, kwargs["quality"]))
            if "fps" in kwargs:
                self.fps = max(1, min(60, kwargs["fps"]))
            if "compression_level" in kwargs:
                self.compression_level = max(1, min(9, kwargs["compression_level"]))
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
