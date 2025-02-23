"""
Script de inicialización de bases de datos.
"""

import sqlite3
import os
import logging
from pathlib import Path

def init_databases(db_path: str = None):
    """
    Inicializa la base de datos con las tablas necesarias.
    
    Args:
        db_path: Ruta de la base de datos. Si es None, se usa la ubicación predeterminada.
    """
    try:
        if db_path is None:
            db_dir = Path(__file__).parent
            db_path = str(db_dir / "bots.db")
        
        # Asegurar que el directorio existe
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Tabla de bots
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
            
            # Tabla de comandos
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id INTEGER,
                command TEXT,
                response TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed BOOLEAN DEFAULT 0,
                success BOOLEAN,
                FOREIGN KEY (bot_id) REFERENCES bots(id)
            )''')
            
            # Tabla de estadísticas
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id INTEGER,
                type TEXT,
                value TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (bot_id) REFERENCES bots(id)
            )''')
            
            # Crear índices
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_bots_unique_id ON bots(unique_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_bot_id ON commands(bot_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_executed ON commands(executed)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_stats_bot_id ON stats(bot_id)')
            
            conn.commit()
            
        print(f"[+] Base de datos inicializada en: {db_path}")
        return True
    
    except Exception as e:
        print(f"[-] Error inicializando base de datos: {e}")
        logging.error(f"Error inicializando base de datos: {e}")
        return False

if __name__ == "__main__":
    init_databases()
