# 🕷️ SPYNET V3.0 - Edición Analista

Una herramienta avanzada de análisis de tráfico de red con interfaz gráfica moderna, geolocalización IP y capacidades de monitoreo en tiempo real.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## 🌟 Características Principales

- **🔍 Análisis de Tráfico en Tiempo Real**: Captura y analiza paquetes de red con detalles completos
- **🌍 Geolocalización IP**: Identifica la ubicación geográfica de las conexiones (requiere base de datos GeoIP)
- **🎯 Filtrado Inteligente**: Sistema de filtros en tiempo real para encontrar conexiones específicas
- **📊 Visualización Gráfica**: Gráficos en tiempo real del tráfico de red
- **🔧 Instalador Automático**: Instala automáticamente todas las dependencias necesarias
- **📱 Escáner de Red**: Descubre dispositivos activos en tu red local
- **💾 Exportación de Datos**: Exporta los resultados a archivos CSV
- **🔒 Detección de Puertos Inseguros**: Identifica conexiones a puertos potencialmente peligrosos

## 📋 Requisitos del Sistema

- **Python 3.7 o superior**
- **Permisos de administrador** (necesarios para la captura de paquetes)
- **Conexión a Internet** (para la instalación automática de dependencias)

### Dependencias Principales
El programa instalará automáticamente:
- `scapy` - Manipulación de paquetes de red
- `psutil` - Información del sistema
- `matplotlib` - Generación de gráficos
- `Pillow (PIL)` - Procesamiento de imágenes
- `maxminddb` - Base de datos de geolocalización

## 🚀 Instalación y Uso

### Instalación Rápida

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/tuusuario/spynet-v3.git
   cd spynet-v3
   ```

2. **Ejecuta el programa:**
   ```bash
   # En Windows (como Administrador)
   python SPYNET_V3.py
   
   # En Linux/macOS
   sudo python3 SPYNET_V3.py
   ```

3. **El instalador automático se encargará del resto** ✨

### Configuración de GeoIP (Opcional)

Para habilitar la geolocalización de IPs:

1. Crea una carpeta llamada `geoip` en el directorio del programa
2. Descarga la base de datos GeoLite2-City desde [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
3. Coloca el archivo `GeoLite2-City.mmdb` en la carpeta `geoip/`

### Estructura de Carpetas

```
spynet-v3/
├── SPYNET_V3.py           # Archivo principal
├── icons/                 # Iconos de la interfaz
│   ├── telarana.png      # Icono principal
│   ├── start.png         # Icono de inicio
│   ├── stop.png          # Icono de parar
│   ├── clear.png         # Icono de limpiar
│   ├── csv.png           # Icono de CSV
│   ├── scan.png          # Icono de escáner
│   └── export.png        # Icono de exportar
├── geoip/                # Base de datos GeoIP (opcional)
│   └── GeoLite2-City.mmdb
└── README.md
```

## 🎮 Cómo Usar

### 1. Interfaz Principal

La aplicación cuenta con tres pestañas principales:

#### 📊 **Análisis de Tráfico**
- Muestra conexiones en tiempo real con geolocalización
- Filtros de búsqueda instantánea
- Doble clic en cualquier conexión para ver detalles completos del paquete
- Identificación automática de puertos inseguros (resaltados en rojo)

#### 🌐 **Dispositivos en Red**
- Escanea y lista todos los dispositivos conectados a tu red
- Muestra IP, MAC, fabricante y nombre del host
- Estado de conexión en tiempo real

#### 📈 **Visualización**
- Gráfico en tiempo real del tráfico de red
- Medición en KB/s
- Historial de los últimos 5 minutos

### 2. Controles Principales

| Botón | Función |
|-------|---------|
| ▶️ | Iniciar monitoreo de tráfico |
| ⏹️ | Detener monitoreo |
| 🗑️ | Limpiar datos capturados |
| 📄 | Abrir archivo CSV guardado |
| 💾 | Exportar datos actuales a CSV |
| 🔍 | Escanear dispositivos en red |

### 3. Sistema de Filtros

El campo de filtro permite buscar en tiempo real:
- **Por IP**: `192.168.1.100`
- **Por dominio**: `google.com`
- **Por protocolo**: `TCP`, `UDP`, `ICMP`
- **Por puerto**: `80`, `443`, `22`
- **Por país**: `US`, `ES`, `MX`

## 🔧 Características Técnicas

### Protocolos Soportados
- **TCP** - Protocolo de Control de Transmisión
- **UDP** - Protocolo de Datagramas de Usuario
- **ICMP** - Protocolo de Mensajes de Control de Internet
- **ARP** - Protocolo de Resolución de Direcciones

### Puertos Monitoreados como Inseguros
- **Puerto 80** - HTTP (sin cifrado)
- **Puerto 21** - FTP
- **Puerto 23** - Telnet
- **Puerto 25** - SMTP
- **Puerto 110** - POP3

### Capacidades de Análisis
- Resolución de nombres de dominio
- Identificación de fabricantes por MAC
- Cálculo de tráfico en tiempo real
- Detección de redes privadas vs públicas

## 🛡️ Consideraciones de Seguridad

⚠️ **IMPORTANTE**: Esta herramienta está diseñada para:
- Análisis de tu propia red
- Propósitos educativos y de investigación
- Administración de sistemas legítima

❌ **NO usar para**:
- Interceptar tráfico sin autorización
- Actividades ilegales o no autorizadas
- Violación de la privacidad de terceros

## 🐛 Solución de Problemas

### Problemas Comunes

**Error de permisos:**
```
Solution: Ejecutar como administrador/sudo
Windows: Clic derecho → "Ejecutar como administrador"
Linux/macOS: sudo python3 SPYNET_V3.py
```

**No se instalan las dependencias:**
```
Solución manual:
pip install scapy psutil matplotlib Pillow maxminddb
```

**No aparecen iconos:**
```
Verificar que existe la carpeta 'icons/' con todos los archivos PNG
```

**GeoIP no funciona:**
```
Descargar GeoLite2-City.mmdb y colocar en carpeta 'geoip/'
```

## 📊 Exportación de Datos

Los datos se pueden exportar en formato CSV con las siguientes columnas:

| Columna | Descripción |
|---------|-------------|
| Tiempo | Timestamp de la conexión |
| País | Código de país de la IP origen |
| Origen | Dirección IP de origen |
| Destino | Dirección IP de destino |
| Dominio | Nombre de dominio resuelto |
| Protocolo | TCP/UDP/ICMP |
| Puerto | Puerto de destino |
| Tamaño | Tamaño del paquete en bytes |
| Detalles | Información adicional |


## 📝 Changelog

### v3.0 - Edición Analista
- ✅ Sistema de geolocalización IP
- ✅ Filtros en tiempo real
- ✅ Ventana de detalles de paquetes
- ✅ Mejoras en la interfaz gráfica
- ✅ Instalador automático mejorado

### v2.1
- ✅ Instalador automático de dependencias
- ✅ Mejoras en la captura de paquetes

### v2.0
- ✅ Interfaz gráfica con pestañas
- ✅ Escáner de red integrado
- ✅ Gráficos en tiempo real

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE.txt` para más detalles.

## 👨‍💻 Autor

- **Ever Leiva** - *Desarrollador Principal* - [@ever](https://github.com/ever186)

## 🙏 Agradecimientos

- **Scapy Team** - Por la excelente librería de manipulación de paquetes
- **MaxMind** - Por la base de datos GeoIP gratuita
- **Python Community** - Por las increíbles librerías que hacen esto posible

---

⭐ **¡Si te gusta este proyecto, dale una estrella!** ⭐

## 🔗 Enlaces Útiles

- [Documentación de Scapy](https://scapy.readthedocs.io/)
- [GeoLite2 Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- [Python Official Website](https://www.python.org/)

---

*Desarrollado con ❤️ para la comunidad de ciberseguridad*
