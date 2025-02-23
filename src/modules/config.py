"""
Configuración compartida para los módulos.
"""

from pathlib import Path

# Rutas base
BASE_DIR = Path(__file__).parent.parent
MODULES_DIR = BASE_DIR / "modules"
DB_DIR = BASE_DIR / "bbdd"
LOGS_DIR = BASE_DIR / "logs"
TEMP_DIR = BASE_DIR / "temp"

# Asegurar que existan los directorios necesarios
for directory in [DB_DIR, LOGS_DIR, TEMP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Configuración de bases de datos
DB_CONFIG = {
    "bots": str(DB_DIR / "bots.db"),
    "commands": str(DB_DIR / "commands.db"),
    "stats": str(DB_DIR / "stats.db")
}

# Configuración de módulos
MODULE_CONFIG = {
    "max_command_history": 1000,
    "command_timeout": 30,
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "allowed_file_types": [".txt", ".log", ".py", ".ps1", ".bat", ".sh"],
    "blocked_commands": ["format", "mkfs", "dd", "rm -rf /"],
    "stats_interval": 60,  # segundos
    "cleanup_interval": 3600  # 1 hora
}
