"""
Módulo de estadísticas y monitoreo.
Recopila y analiza estadísticas de los bots y el servidor.
"""

import psutil
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import threading

@dataclass
class BotActivity:
    bot_id: int
    command: str
    timestamp: datetime
    execution_time: float
    success: bool
    resource_usage: Dict

class StatsMonitor:
    def __init__(self, db_manager):
        """Inicializa el monitor de estadísticas."""
        self.db = db_manager
        self.activities: List[BotActivity] = []
        self.is_monitoring = False
        self._monitor_thread = None
        self.server_stats = {
            "start_time": datetime.now(),
            "total_commands": 0,
            "failed_commands": 0,
            "active_bots": 0,
            "peak_bots": 0,
            "data_transferred": 0
        }

    def start_monitoring(self):
        """Inicia el monitoreo de estadísticas."""
        self.is_monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self):
        """Detiene el monitoreo."""
        self.is_monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)

    def _monitor_loop(self):
        """Bucle principal de monitoreo."""
        while self.is_monitoring:
            try:
                self._update_server_stats()
                self._check_anomalies()
                time.sleep(60)  # Actualizar cada minuto
            except Exception as e:
                logging.error(f"Error en monitoreo: {e}")

    def _update_server_stats(self):
        """Actualiza estadísticas del servidor."""
        try:
            active_bots = len(self.db.get_active_bots())
            self.server_stats["active_bots"] = active_bots
            self.server_stats["peak_bots"] = max(self.server_stats["peak_bots"], active_bots)
            
            # Estadísticas del sistema
            cpu_usage = psutil.cpu_percent(interval=1)
            mem_usage = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage('/').percent
            
            # Guardar en base de datos
            self.db.store_system_stats({
                "timestamp": datetime.now(),
                "cpu_usage": cpu_usage,
                "mem_usage": mem_usage,
                "disk_usage": disk_usage,
                "active_bots": active_bots
            })
        except Exception as e:
            logging.error(f"Error actualizando estadísticas: {e}")

    def _check_anomalies(self):
        """Detecta anomalías en el comportamiento."""
        try:
            # Verificar uso excesivo de recursos
            if psutil.cpu_percent() > 90 or psutil.virtual_memory().percent > 90:
                self._trigger_alert("HIGH_RESOURCE_USAGE")

            # Verificar desconexiones masivas
            current_bots = len(self.db.get_active_bots())
            if current_bots < self.server_stats["active_bots"] * 0.5:
                self._trigger_alert("MASS_DISCONNECTION")

            # Verificar comandos fallidos
            recent_commands = self.db.get_recent_commands(limit=100)
            failed_commands = sum(1 for cmd in recent_commands if not cmd["success"])
            if failed_commands > 10:
                self._trigger_alert("HIGH_FAILURE_RATE")

        except Exception as e:
            logging.error(f"Error verificando anomalías: {e}")

    def _trigger_alert(self, alert_type: str, details: Dict = None):
        """Registra y notifica alertas."""
        try:
            alert = {
                "type": alert_type,
                "timestamp": datetime.now(),
                "details": details or {},
                "server_stats": self.get_current_stats()
            }
            self.db.store_alert(alert)
            logging.warning(f"Alerta: {alert_type} - {details}")
        except Exception as e:
            logging.error(f"Error generando alerta: {e}")

    def record_command(self, bot_id: int, command: str, execution_time: float, success: bool):
        """Registra la ejecución de un comando."""
        try:
            activity = BotActivity(
                bot_id=bot_id,
                command=command,
                timestamp=datetime.now(),
                execution_time=execution_time,
                success=success,
                resource_usage={
                    "cpu": psutil.cpu_percent(),
                    "memory": psutil.virtual_memory().percent
                }
            )
            self.activities.append(activity)
            self.server_stats["total_commands"] += 1
            if not success:
                self.server_stats["failed_commands"] += 1

            # Mantener solo las últimas 1000 actividades
            if len(self.activities) > 1000:
                self.activities = self.activities[-1000:]

        except Exception as e:
            logging.error(f"Error registrando comando: {e}")

    def get_bot_stats(self, bot_id: int) -> Dict:
        """Obtiene estadísticas de un bot específico."""
        try:
            bot_activities = [a for a in self.activities if a.bot_id == bot_id]
            total_commands = len(bot_activities)
            if not total_commands:
                return {}

            successful_commands = len([a for a in bot_activities if a.success])
            avg_execution_time = sum(a.execution_time for a in bot_activities) / total_commands

            return {
                "total_commands": total_commands,
                "successful_commands": successful_commands,
                "failed_commands": total_commands - successful_commands,
                "success_rate": (successful_commands / total_commands) * 100,
                "average_execution_time": avg_execution_time,
                "last_seen": max(a.timestamp for a in bot_activities),
                "common_commands": self._get_common_commands(bot_activities)
            }
        except Exception as e:
            logging.error(f"Error obteniendo estadísticas del bot: {e}")
            return {}

    def _get_common_commands(self, activities: List[BotActivity]) -> List[Dict]:
        """Analiza los comandos más comunes."""
        try:
            command_count = {}
            for activity in activities:
                command_count[activity.command] = command_count.get(activity.command, 0) + 1

            return sorted(
                [{"command": cmd, "count": count} for cmd, count in command_count.items()],
                key=lambda x: x["count"],
                reverse=True
            )[:5]  # Top 5 comandos más usados
        except Exception as e:
            logging.error(f"Error analizando comandos comunes: {e}")
            return []

    def get_current_stats(self) -> Dict:
        """Obtiene estadísticas actuales del servidor."""
        try:
            uptime = (datetime.now() - self.server_stats["start_time"]).total_seconds()
            active_bots = len(self.db.get_active_bots())

            return {
                **self.server_stats,
                "uptime": uptime,
                "active_bots": active_bots,
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "command_success_rate": (
                    (self.server_stats["total_commands"] - self.server_stats["failed_commands"]) /
                    self.server_stats["total_commands"] * 100
                ) if self.server_stats["total_commands"] > 0 else 0
            }
        except Exception as e:
            logging.error(f"Error obteniendo estadísticas actuales: {e}")
            return {}

    def generate_report(self, report_type: str = "full") -> Dict:
        """Genera un reporte detallado."""
        try:
            if report_type == "full":
                return {
                    "server_stats": self.get_current_stats(),
                    "bot_stats": {
                        bot["id"]: self.get_bot_stats(bot["id"])
                        for bot in self.db.get_active_bots()
                    },
                    "recent_activities": [
                        {
                            "bot_id": a.bot_id,
                            "command": a.command,
                            "timestamp": a.timestamp.isoformat(),
                            "success": a.success,
                            "execution_time": a.execution_time
                        }
                        for a in sorted(
                            self.activities,
                            key=lambda x: x.timestamp,
                            reverse=True
                        )[:50]  # Últimas 50 actividades
                    ],
                    "alerts": self.db.get_recent_alerts(limit=10)
                }
            elif report_type == "summary":
                return {
                    "total_bots": len(self.db.get_active_bots()),
                    "total_commands": self.server_stats["total_commands"],
                    "success_rate": (
                        (self.server_stats["total_commands"] - self.server_stats["failed_commands"]) /
                        self.server_stats["total_commands"] * 100
                    ) if self.server_stats["total_commands"] > 0 else 0,
                    "uptime": (datetime.now() - self.server_stats["start_time"]).total_seconds()
                }
            else:
                raise ValueError(f"Tipo de reporte no válido: {report_type}")

        except Exception as e:
            logging.error(f"Error generando reporte: {e}")
            return {}
