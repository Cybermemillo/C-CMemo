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
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Tabla principal de bots
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS bots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    unique_id TEXT UNIQUE,
                    ip_address TEXT,
                    system_info TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    metadata TEXT
                )''')

                # Tabla de comandos y respuestas
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id INTEGER,
                    command TEXT,
                    response TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN,
                    FOREIGN KEY (bot_id) REFERENCES bots(id)
                )''')

                # Tabla de estadísticas
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    type TEXT,
                    value TEXT,
                    bot_id INTEGER,
                    FOREIGN KEY (bot_id) REFERENCES bots(id)
                )''')

                # Índices para mejorar rendimiento
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_bots_unique_id ON bots(unique_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_bot_id ON commands(bot_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_stats_bot_id ON stats(bot_id)')
                
                conn.commit()
        except Exception as e:
            logging.error(f"Error inicializando base de datos: {e}")
            raise

    def register_bot(self, unique_id: str, ip_address: str, system_info: Dict) -> int:
        """Registra o actualiza un bot en la base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()

                # Intentar actualizar primero
                cursor.execute('''
                UPDATE bots 
                SET ip_address = ?, system_info = ?, last_seen = ?, is_active = 1
                WHERE unique_id = ?
                ''', (ip_address, json.dumps(system_info), now, unique_id))

                # Si no existe, insertar
                if cursor.rowcount == 0:
                    cursor.execute('''
                    INSERT INTO bots (unique_id, ip_address, system_info, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ''', (unique_id, ip_address, json.dumps(system_info), now, now))

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
