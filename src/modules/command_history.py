"""
Módulo de historial de comandos.
Mantiene un registro detallado de comandos y sus resultados.
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union
import hashlib

class CommandHistory:
    def __init__(self, db_path: str):
        """Inicializa el gestor de historial."""
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Inicializa la base de datos de historial."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla de comandos
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bot_id INTEGER,
                    command TEXT,
                    command_type TEXT,
                    arguments JSON,
                    timestamp TIMESTAMP,
                    execution_time FLOAT,
                    success BOOLEAN,
                    result TEXT,
                    error_message TEXT,
                    hash TEXT
                )''')

                # Tabla de tags
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_tags (
                    command_id INTEGER,
                    tag TEXT,
                    FOREIGN KEY (command_id) REFERENCES command_history(id)
                )''')

                conn.commit()
        except Exception as e:
            logging.error(f"Error inicializando base de datos de historial: {e}")
            raise

    def add_command(self, bot_id: int, command: str, command_type: str,
                   arguments: Dict = None, tags: List[str] = None) -> int:
        """
        Añade un nuevo comando al historial.
        
        Returns:
            ID del comando en el historial
        """
        try:
            timestamp = datetime.now()
            command_hash = hashlib.sha256(
                f"{bot_id}{command}{timestamp.isoformat()}".encode()
            ).hexdigest()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO command_history 
                (bot_id, command, command_type, arguments, timestamp, hash)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    bot_id, command, command_type,
                    json.dumps(arguments) if arguments else None,
                    timestamp, command_hash
                ))
                
                command_id = cursor.lastrowid

                # Añadir tags si existen
                if tags:
                    cursor.executemany(
                        'INSERT INTO command_tags (command_id, tag) VALUES (?, ?)',
                        [(command_id, tag) for tag in tags]
                    )

                conn.commit()
                return command_id

        except Exception as e:
            logging.error(f"Error añadiendo comando al historial: {e}")
            raise

    def update_result(self, command_id: int, success: bool, result: str = None,
                     error_message: str = None, execution_time: float = None):
        """Actualiza el resultado de un comando."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE command_history 
                SET success = ?, result = ?, error_message = ?, execution_time = ?
                WHERE id = ?
                ''', (success, result, error_message, execution_time, command_id))
                conn.commit()
        except Exception as e:
            logging.error(f"Error actualizando resultado: {e}")
            raise

    def get_command_history(self, bot_id: Optional[int] = None,
                          limit: int = 100, offset: int = 0,
                          tags: List[str] = None) -> List[Dict]:
        """Obtiene el historial de comandos con filtros."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = '''
                SELECT DISTINCT h.*, GROUP_CONCAT(t.tag) as tags
                FROM command_history h
                LEFT JOIN command_tags t ON h.id = t.command_id
                '''
                params = []

                # Aplicar filtros
                conditions = []
                if bot_id is not None:
                    conditions.append("h.bot_id = ?")
                    params.append(bot_id)

                if tags:
                    placeholders = ','.join(['?'] * len(tags))
                    conditions.append(f'''
                        h.id IN (
                            SELECT command_id 
                            FROM command_tags 
                            WHERE tag IN ({placeholders})
                            GROUP BY command_id 
                            HAVING COUNT(DISTINCT tag) = ?
                        )
                    ''')
                    params.extend(tags)
                    params.append(len(tags))

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += '''
                GROUP BY h.id
                ORDER BY h.timestamp DESC
                LIMIT ? OFFSET ?
                '''
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [{
                    **dict(row),
                    'arguments': json.loads(row['arguments']) if row['arguments'] else None,
                    'tags': row['tags'].split(',') if row['tags'] else []
                } for row in rows]

        except Exception as e:
            logging.error(f"Error obteniendo historial: {e}")
            return []

    def add_tags(self, command_id: int, tags: List[str]):
        """Añade tags a un comando existente."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.executemany(
                    'INSERT OR IGNORE INTO command_tags (command_id, tag) VALUES (?, ?)',
                    [(command_id, tag) for tag in tags]
                )
                conn.commit()
        except Exception as e:
            logging.error(f"Error añadiendo tags: {e}")
            raise

    def search_commands(self, query: str) -> List[Dict]:
        """Busca comandos por texto."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT DISTINCT h.*, GROUP_CONCAT(t.tag) as tags
                FROM command_history h
                LEFT JOIN command_tags t ON h.id = t.command_id
                WHERE h.command LIKE ? OR h.result LIKE ?
                GROUP BY h.id
                ORDER BY h.timestamp DESC
                ''', (f'%{query}%', f'%{query}%'))
                
                rows = cursor.fetchall()
                return [{
                    **dict(row),
                    'arguments': json.loads(row['arguments']) if row['arguments'] else None,
                    'tags': row['tags'].split(',') if row['tags'] else []
                } for row in rows]

        except Exception as e:
            logging.error(f"Error buscando comandos: {e}")
            return []

    def get_command_stats(self, bot_id: Optional[int] = None) -> Dict:
        """Obtiene estadísticas de comandos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                where_clause = "WHERE bot_id = ?" if bot_id else ""
                params = [bot_id] if bot_id else []

                cursor.execute(f'''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    AVG(execution_time) as avg_time,
                    command_type,
                    COUNT(DISTINCT bot_id) as unique_bots
                FROM command_history
                {where_clause}
                GROUP BY command_type
                ''', params)

                stats = {}
                for row in cursor.fetchall():
                    stats[row[3]] = {
                        'total': row[0],
                        'successful': row[1],
                        'avg_execution_time': row[2],
                        'unique_bots': row[4]
                    }

                return stats

        except Exception as e:
            logging.error(f"Error obteniendo estadísticas: {e}")
            return {}
