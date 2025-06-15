# 📊 Tutorial de Instalación - SPYNET

## 📋 Requisitos del Sistema

### Sistemas Operativos Compatibles
- ✅ Windows 10/11
- ✅ macOS 10.14+
- ✅ Linux (Ubuntu, Debian, CentOS, etc.)

### Requisitos de Hardware
- 🖥️ **RAM**: Mínimo 4GB (Recomendado 8GB)
- 💾 **Espacio**: 500MB libres
- 🌐 **Red**: Tarjeta de red activa
- 👤 **Permisos**: Acceso de administrador/root

---

## 🐍 Paso 1: Instalar Python

### Windows
1. Ve a [python.org](https://www.python.org/downloads/)
2. Descarga Python 3.8 o superior
3. **IMPORTANTE**: Marca "Add Python to PATH" durante la instalación
4. Verifica la instalación:
   ```cmd
   python --version
   pip --version
   ```

### macOS
```bash
# Usando Homebrew (recomendado)
brew install python3

# O descarga desde python.org
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip
```

### Linux (CentOS/RHEL)
```bash
sudo yum install python3 python3-pip
# O para versiones más nuevas:
sudo dnf install python3 python3-pip
```

---

## 📦 Paso 2: Instalar Dependencias (Actualizacion de la V3.0)
**⚠️con la version V3 ya existe un instaldor para las dependencias necesarias, en caso de que el programa no pueda instarlo realizar los siguientes pasos⚠️**
### Instalación Automática
Crea un archivo `requirements.txt` con el siguiente contenido:

```txt
tkinter
psutil>=5.8.0
scapy>=2.4.5
```

Luego ejecuta:
```bash
pip install -r requirements.txt
```

### Instalación Manual
```bash
# Dependencias principales
pip install psutil
pip install scapy

# tkinter viene incluido con Python en la mayoría de sistemas
```

### Verificar Instalación de tkinter
```python
# Ejecuta este código para verificar tkinter
import tkinter as tk
root = tk.Tk()
root.title("Prueba tkinter")
tk.Label(root, text="✅ tkinter funciona correctamente").pack()
root.mainloop()
```

---

## 🔧 Paso 3: Configuración Especial por Sistema

### Windows
1. **Ejecutar como Administrador**:
   - Abre CMD como administrador
   - Navega a la carpeta del proyecto
   - Ejecuta el programa

2. **Firewall de Windows**:
   - Puede aparecer una ventana de firewall
   - Permite el acceso para Python

### macOS
```bash
# Instalar dependencias adicionales para Scapy
sudo pip3 install scapy

# Dar permisos de red (puede requerir contraseña)
sudo python3 Aplicacionen_Alpha_Final.py
```

### Linux
```bash
# Instalar dependencias del sistema
sudo apt install python3-tk  # Para tkinter
sudo apt install libpcap-dev  # Para Scapy

# Dar permisos de red
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
# O ejecutar como root:
sudo python3 Aplicacionen_Alpha_Final.py
```

---

## 🚀 Paso 4: Ejecutar la Aplicación

### Método 1: Línea de Comandos
```bash
# Navegar a la carpeta del proyecto
cd /ruta/a/tu/proyecto

# Ejecutar como administrador/root
sudo python3 Aplicacionen_Alpha_Final.py
```

### Método 2: Crear Script de Inicio

#### Windows (`iniciar.bat`)
```batch
@echo off
echo Iniciando Analizador de Red...
python Aplicacionen_Alpha_Final.py
pause
```

#### macOS/Linux (`iniciar.sh`)
```bash
#!/bin/bash
echo "Iniciando Analizador de Red..."
sudo python3 Aplicacionen_Alpha_Final.py
```

Hacer ejecutable:
```bash
chmod +x iniciar.sh
./iniciar.sh
```

---

## 🛠️ Solución de Problemas Comunes

### ❌ Error: "ModuleNotFoundError: No module named 'tkinter'"
**Windows/macOS**: Reinstala Python desde python.org
**Linux**: 
```bash
sudo apt install python3-tk
```

### ❌ Error: "Permission denied" o problemas de red
**Solución**: Ejecutar como administrador/root
```bash
# Linux/macOS
sudo python3 Aplicacionen_Alpha_Final.py

# Windows: Abrir terminal como administrador
```

### ❌ Error: "No module named 'scapy'"
```bash
pip install scapy
# Si falla en Linux:
sudo apt install python3-dev libpcap-dev
pip install scapy
```

### ❌ La aplicación no captura tráfico
1. Verificar permisos de administrador
2. Desactivar VPN temporalmente
3. Verificar firewall/antivirus
4. Ejecutar en red activa (no modo avión)

### ❌ El escaneo de red no encuentra dispositivos
1. Verificar que estés en una red local
2. Algunos routers bloquean escaneos ARP
3. Probar con diferentes rangos de red

---

## 📱 Paso 5: Uso de la Aplicación

### Funciones Principales

1. **📊 Análisis de Tráfico**
   - Clic en "▶ Iniciar Análisis"
   - Observa las conexiones en tiempo real
   - Detén con "⏹ Detener"

2. **🌐 Escaneo de Red**
   - Ve a la pestaña "Dispositivos en Red"
   - Clic en "🔍 Escanear Red"
   - Espera a que termine el escaneo

3. **💾 Exportar Datos**
   - Clic en "💾 Exportar CSV"
   - Se crea un archivo con timestamp
   - Abre con Excel o cualquier editor CSV

### Consejos de Uso
- ⚡ Ejecuta siempre como administrador
- 🔒 Algunas redes corporativas pueden bloquear escaneos
- 📊 Los datos se almacenan solo en memoria hasta exportar
- 🧹 Usa "Limpiar" para resetear la tabla

---

## 🔐 Consideraciones de Seguridad

### ⚠️ Importante
- Esta herramienta requiere permisos elevados
- Solo úsala en redes propias o con autorización
- Algunos antivirus pueden detectarla como sospechosa
- El escaneo de red puede ser detectado por administradores

### 📋 Uso Ético
- ✅ Redes propias o domésticas
- ✅ Diagnóstico de problemas
- ✅ Monitoreo autorizado
- ❌ Redes ajenas sin permiso
- ❌ Actividades maliciosas

---

## 📞 Soporte y Contacto

### Si tienes problemas:
1. Verifica que Python esté correctamente instalado
2. Confirma que todas las dependencias estén instaladas
3. Ejecuta como administrador/root
4. Revisa la sección de solución de problemas

### Archivos Generados
- `trafico_tabla_YYYYMMDD_HHMMSS.csv`: Exportaciones de datos
- Logs de errores aparecen en la consola

---

## 🎯 Resumen de Instalación Rápida

```bash
# 1. Instalar Python 3.8+
# 2. Instalar dependencias
pip install psutil scapy

# 3. Ejecutar como administrador
sudo python3 Aplicacionen_Alpha_Final.py
```

¡Listo! Ya tienes tu analizador de red funcionando. 🎉
