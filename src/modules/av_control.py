"""
Módulo de control de audio y vídeo.
Permite capturar audio del micrófono y video de la webcam.
"""

import cv2
import pyaudio
import wave
import threading
import tempfile
import logging
import base64
import numpy as np
import os
from typing import Optional, Dict, Union
from datetime import datetime

class AudioVideoCapture:
    def __init__(self):
        """Inicializa el controlador de audio/vídeo."""
        self.recording_audio = False
        self.recording_video = False
        self.temp_dir = tempfile.mkdtemp()
        self._setup_devices()
        
    def _setup_devices(self):
        """Configura los dispositivos de audio y vídeo."""
        self.audio = pyaudio.PyAudio()
        self.video_devices = []
        
        try:
            # Enumerar cámaras disponibles
            i = 0
            while True:
                cap = cv2.VideoCapture(i)
                if not cap.read()[0]:
                    break
                self.video_devices.append(i)
                cap.release()
                i += 1
        except Exception as e:
            logging.error(f"Error enumerando dispositivos de vídeo: {e}")

    def start_audio_recording(self, duration: int = 30) -> Dict[str, Union[bool, str]]:
        """
        Inicia la grabación de audio.
        
        Args:
            duration: Duración en segundos
            
        Returns:
            Dict con resultado y ruta del archivo
        """
        if self.recording_audio:
            return {"success": False, "error": "Ya hay una grabación en curso"}
            
        try:
            self.recording_audio = True
            audio_file = os.path.join(self.temp_dir, f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav")
            
            # Configuración de audio
            CHUNK = 1024
            FORMAT = pyaudio.paInt16
            CHANNELS = 1
            RATE = 44100
            
            stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK
            )

            frames = []
            
            # Grabar audio en thread separado
            def record():
                try:
                    for _ in range(0, int(RATE / CHUNK * duration)):
                        if not self.recording_audio:
                            break
                        data = stream.read(CHUNK)
                        frames.append(data)
                finally:
                    stream.stop_stream()
                    stream.close()
                    
                    with wave.open(audio_file, 'wb') as wf:
                        wf.setnchannels(CHANNELS)
                        wf.setsampwidth(self.audio.get_sample_size(FORMAT))
                        wf.setframerate(RATE)
                        wf.writeframes(b''.join(frames))
                    
                    self.recording_audio = False
            
            threading.Thread(target=record, daemon=True).start()
            return {"success": True, "file": audio_file}
            
        except Exception as e:
            self.recording_audio = False
            return {"success": False, "error": str(e)}

    def stop_audio_recording(self) -> Dict[str, bool]:
        """Detiene la grabación de audio."""
        self.recording_audio = False
        return {"success": True}

    def capture_webcam_image(self, device_id: int = 0) -> Dict[str, Union[bool, str]]:
        """
        Captura una imagen de la webcam.
        
        Args:
            device_id: ID del dispositivo de vídeo
            
        Returns:
            Dict con la imagen en base64
        """
        try:
            cap = cv2.VideoCapture(device_id)
            if not cap.isOpened():
                return {"success": False, "error": "No se pudo abrir la cámara"}
                
            ret, frame = cap.read()
            if not ret:
                return {"success": False, "error": "No se pudo capturar imagen"}
                
            # Convertir a JPG en memoria
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                return {"success": False, "error": "Error codificando imagen"}
                
            # Convertir a base64
            image_b64 = base64.b64encode(buffer).decode()
            
            return {
                "success": True,
                "image": f"data:image/jpeg;base64,{image_b64}"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if 'cap' in locals():
                cap.release()

    def start_video_recording(self, duration: int = 30, device_id: int = 0) -> Dict[str, Union[bool, str]]:
        """
        Inicia la grabación de vídeo.
        
        Args:
            duration: Duración en segundos
            device_id: ID del dispositivo de vídeo
            
        Returns:
            Dict con resultado y ruta del archivo
        """
        if self.recording_video:
            return {"success": False, "error": "Ya hay una grabación en curso"}
            
        try:
            self.recording_video = True
            video_file = os.path.join(self.temp_dir, f"video_{datetime.now().strftime('%Y%m%d_%H%M%S')}.avi")
            
            cap = cv2.VideoCapture(device_id)
            if not cap.isOpened():
                return {"success": False, "error": "No se pudo abrir la cámara"}
                
            # Configuración de vídeo
            fps = 20.0
            frame_width = int(cap.get(3))
            frame_height = int(cap.get(4))
            
            out = cv2.VideoWriter(
                video_file,
                cv2.VideoWriter_fourcc(*'XVID'),
                fps,
                (frame_width, frame_height)
            )
            
            def record():
                try:
                    start_time = datetime.now()
                    while self.recording_video:
                        ret, frame = cap.read()
                        if not ret:
                            break
                            
                        out.write(frame)
                        
                        # Verificar duración
                        if (datetime.now() - start_time).seconds >= duration:
                            break
                finally:
                    cap.release()
                    out.release()
                    self.recording_video = False
            
            threading.Thread(target=record, daemon=True).start()
            return {"success": True, "file": video_file}
            
        except Exception as e:
            self.recording_video = False
            return {"success": False, "error": str(e)}

    def stop_video_recording(self) -> Dict[str, bool]:
        """Detiene la grabación de vídeo."""
        self.recording_video = False
        return {"success": True}

    def get_device_info(self) -> Dict[str, list]:
        """
        Obtiene información sobre los dispositivos disponibles.
        
        Returns:
            Dict con información de dispositivos de audio y vídeo
        """
        try:
            audio_devices = []
            video_devices = []
            
            # Enumerar dispositivos de audio
            for i in range(self.audio.get_device_count()):
                try:
                    info = self.audio.get_device_info_by_index(i)
                    if info['maxInputChannels'] > 0:
                        audio_devices.append({
                            'index': i,
                            'name': info['name'],
                            'channels': info['maxInputChannels'],
                            'rate': info['defaultSampleRate']
                        })
                except:
                    continue
            
            # Enumerar dispositivos de vídeo
            for i in self.video_devices:
                try:
                    cap = cv2.VideoCapture(i)
                    width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
                    height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
                    fps = cap.get(cv2.CAP_PROP_FPS)
                    cap.release()
                    
                    video_devices.append({
                        'index': i,
                        'resolution': f"{int(width)}x{int(height)}",
                        'fps': round(fps, 2)
                    })
                except:
                    continue
            
            return {
                "audio_devices": audio_devices,
                "video_devices": video_devices
            }
            
        except Exception as e:
            logging.error(f"Error obteniendo información de dispositivos: {e}")
            return {"audio_devices": [], "video_devices": []}

    def cleanup(self):
        """Limpia recursos y archivos temporales."""
        try:
            self.recording_audio = False
            self.recording_video = False
            self.audio.terminate()
            
            # Eliminar archivos temporales
            for file in os.listdir(self.temp_dir):
                try:
                    os.remove(os.path.join(self.temp_dir, file))
                except:
                    pass
            os.rmdir(self.temp_dir)
        except Exception as e:
            logging.error(f"Error en cleanup: {e}")
