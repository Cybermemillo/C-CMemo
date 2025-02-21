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

## 🔧 Instalación

```bash
git clone https://github.com/cybermemillo/c2memo.git
cd c2memo
python3 servidor.py
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

## 🔮 Futuras mejoras

- 🔑 Implementación de autenticación para bots para evitar la conexión de bots no autorizados.
- 📶 Uso de técnicas de evasión para análisis forense, como el encubrimiento de tráfico en protocolos legítimos.
- 🕵️‍♂️ Incorporación de técnicas de ofuscación en la comunicación.
- 📜 Registro detallado de comandos y respuestas para auditoría y depuración.

/C-CMEMO/              ← 📌 Carpeta principal del proyecto
│── /config/           ← 📌 Configuración del proyecto
│   └── config.ini
│── /docs/             ← 📌 Documentación
│   ├── LICENSE.md
│   └── README.md
│── /logs/             ← 📌 Aquí se guardarán los logs
│   └── client.log
│── /src/              ← 📌 Código fuente
│   ├── /bbdd/         ← 📌 Base de datos
│   │   └── bots.bd
│   ├── clienteinfectado.py
│   └── servidor.py

## ⚠️ Nota Importante

Este proyecto está diseñado únicamente para uso en entornos de prueba y con propósitos educativos. No se debe utilizar para actividades no autorizadas.
