import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
import sys
import subprocess
import os
import csv
import socket
import webbrowser
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import platform

# Verificar dependencias
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG_FILE = "trafico_red.csv"

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Tiempo", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Comentario"])

def resolve_ip(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except Exception:
        return ip_address

class NetworkAnalyzer:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("SPYNET")
        self.window.geometry("1400x800")  # Aumenté más el tamaño para las dos pestañas
        self.window.configure(bg='#f0f0f0')
        self.window.iconbitmap("telarana.ico")

        self.monitoring_active = False
        self.analysis_thread = None
        self.connection_count = 0
        self.update_interval = 2
        self.network_devices = []
        self.table_data = []  # Lista para almacenar solo los datos de la tabla

        self.setup_interface()
        self.check_tools()

    def setup_interface(self):
        main_container = tk.Frame(self.window, bg='#f0f0f0')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header_frame = tk.Frame(main_container, bg='#f0f0f0')
        header_frame.pack(fill=tk.X, pady=(0, 20))

        tk.Label(header_frame, text="📊 SPYNET  V1.0",
                 font=("Segoe UI", 16, "bold"), bg='#f0f0f0', fg='#2c3e50').pack()
        tk.Label(header_frame, text="Herramienta profesional para análisis de conectividad",
                 font=("Segoe UI", 10), bg='#f0f0f0', fg='#7f8c8d').pack()

        control_panel = tk.LabelFrame(main_container, text="Panel de Control",
                                      font=("Segoe UI", 10, "bold"), bg='#ecf0f1', fg='#2c3e50', padx=15, pady=10)
        control_panel.pack(fill=tk.X, pady=(0, 20))

        button_frame = tk.Frame(control_panel, bg='#ecf0f1')
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="▶ Iniciar Análisis", command=self.start_monitoring,
                                      bg='#3498db', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_button = tk.Button(button_frame, text="⏹ Detener", command=self.stop_monitoring,
                                     bg='#e74c3c', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_button = tk.Button(button_frame, text="🗑 Limpiar", command=self.clear_data,
                                      bg='#f39c12', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6)
        self.clear_button.pack(side=tk.LEFT)

        self.open_csv_button = tk.Button(button_frame, text="📁 Ver CSV", command=self.open_csv,
                                         bg='#1abc9c', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6)
        self.open_csv_button.pack(side=tk.LEFT, padx=(10, 0))

        self.scan_button = tk.Button(button_frame, text="🔍 Escanear Red", command=self.scan_network,
                                     bg='#9b59b6', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6)
        self.scan_button.pack(side=tk.LEFT, padx=(10, 0))

        self.export_button = tk.Button(button_frame, text="💾 Exportar CSV", command=self.export_table_to_csv,
                                       bg='#34495e', fg='white', font=("Segoe UI", 10, "bold"), padx=20, pady=6)
        self.export_button.pack(side=tk.LEFT, padx=(10, 0))

        self.status_info = tk.Label(control_panel, text="Estado: Detenido | Conexiones: 0",
                                    font=("Segoe UI", 10), bg='#ecf0f1', fg='#2c3e50')
        self.status_info.pack(pady=(10, 0))

        notebook = ttk.Notebook(main_container)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Pestaña de análisis de tráfico
        self.traffic_frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.traffic_frame, text="📊 Análisis de Tráfico")

        # Pestaña de dispositivos de red
        self.devices_frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.devices_frame, text="🌐 Dispositivos en Red")

        self.setup_traffic_table()
        self.setup_devices_table()

    def setup_traffic_table(self):
        frame = tk.Frame(self.traffic_frame, bg='#ffffff')
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Añadí la columna "Dominio" entre "Destino" y "Protocolo"
        cols = ("Tiempo", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Detalles")
        self.traffic_tree = ttk.Treeview(frame, columns=cols, show="headings", height=15)
        
        # Configurar encabezados y anchos de columna
        for col in cols:
            self.traffic_tree.heading(col, text=col)
            
        # Configurar anchos específicos para cada columna
        self.traffic_tree.column("Tiempo", width=80)
        self.traffic_tree.column("Origen", width=120)
        self.traffic_tree.column("Destino", width=120)
        self.traffic_tree.column("Dominio", width=200)  # Columna más ancha para dominios
        self.traffic_tree.column("Protocolo", width=80)
        self.traffic_tree.column("Puerto", width=60)
        self.traffic_tree.column("Tamaño", width=80)
        self.traffic_tree.column("Detalles", width=250)
        
        # Agregar scrollbar horizontal
        h_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.traffic_tree.xview)
        self.traffic_tree.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Agregar scrollbar vertical
        v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=v_scrollbar.set)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.traffic_tree.pack(fill=tk.BOTH, expand=True)

    def setup_devices_table(self):
        frame = tk.Frame(self.devices_frame, bg='#ffffff')
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Información sobre el escaneo
        info_label = tk.Label(frame, text="💡 Haz clic en 'Escanear Red' para ver todos los dispositivos conectados",
                              font=("Segoe UI", 10), bg='#ffffff', fg='#7f8c8d')
        info_label.pack(pady=(0, 10))
        
        # Columnas para la tabla de dispositivos
        device_cols = ("IP", "MAC", "Fabricante", "Nombre del Host", "Estado", "Tiempo de Respuesta")
        self.devices_tree = ttk.Treeview(frame, columns=device_cols, show="headings", height=15)
        
        # Configurar encabezados y anchos
        for col in device_cols:
            self.devices_tree.heading(col, text=col)
            
        self.devices_tree.column("IP", width=120)
        self.devices_tree.column("MAC", width=140)
        self.devices_tree.column("Fabricante", width=150)
        self.devices_tree.column("Nombre del Host", width=200)
        self.devices_tree.column("Estado", width=80)
        self.devices_tree.column("Tiempo de Respuesta", width=120)
        
        # Scrollbars para dispositivos
        d_h_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.devices_tree.xview)
        self.devices_tree.configure(xscrollcommand=d_h_scrollbar.set)
        d_h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        d_v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=d_v_scrollbar.set)
        d_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.devices_tree.pack(fill=tk.BOTH, expand=True)

    def check_tools(self):
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Falta Scapy", "Debes instalar 'scapy' para capturar tráfico: pip install scapy")

    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.connection_count = 0
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.update_status("Analizando", 0)

            if SCAPY_AVAILABLE:
                self.traffic_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
                self.traffic_thread.start()

    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.update_status("Detenido", self.connection_count)

    def clear_data(self):
        for i in self.traffic_tree.get_children():
            self.traffic_tree.delete(i)
        self.table_data.clear()  # Limpiar también los datos de la tabla
        self.connection_count = 0
        self.update_status("Detenido", 0)

    def update_status(self, status, count):
        self.status_info.config(text=f"Estado: {status} | Conexiones: {count}")

    def get_network_range(self):
        """Obtiene el rango de red local"""
        try:
            # Obtener la IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Crear el rango de red (asumiendo /24)
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
        except Exception as e:
            return "192.168.1.0/24"  # Fallback común

    def ping_host(self, ip):
        """Hace ping a un host específico"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=3)
            return result.returncode == 0
        except:
            return False

    def get_mac_vendor(self, mac):
        """Obtiene el fabricante basado en la MAC (simplificado)"""
        mac_vendors = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:16:3E": "Xen",
            "00:1B:21": "Intel",
            "00:1F:3C": "Apple",
            "28:CD:C1": "Apple",
            "F0:18:98": "Apple",
            "AC:DE:48": "Apple",
            "00:22:58": "Hewlett Packard",
            "00:24:81": "Samsung",
            "00:26:BB": "Samsung"
        }
        
        if mac and len(mac) >= 8:
            prefix = mac[:8].upper()
            return mac_vendors.get(prefix, "Desconocido")
        return "Desconocido"

    def scan_network(self):
        """Escanea la red local para encontrar dispositivos"""
        self.scan_button.config(state=tk.DISABLED, text="🔄 Escaneando...")
        
        # Limpiar tabla anterior
        for i in self.devices_tree.get_children():
            self.devices_tree.delete(i)
        
        def scan_worker():
            try:
                network_range = self.get_network_range()
                network = ipaddress.ip_network(network_range)
                
                # Crear paquete ARP para escaneo
                if SCAPY_AVAILABLE:
                    arp_request = ARP(pdst=str(network))
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    
                    # Enviar paquetes y recibir respuestas
                    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                    
                    devices = []
                    for element in answered_list:
                        device = {
                            'ip': element[1].psrc,
                            'mac': element[1].hwsrc,
                            'vendor': self.get_mac_vendor(element[1].hwsrc),
                            'hostname': resolve_ip(element[1].psrc),
                            'status': 'Activo',
                            'response_time': '< 2s'
                        }
                        devices.append(device)
                    
                    # Actualizar tabla en el hilo principal
                    self.window.after(0, self.update_devices_table, devices)
                else:
                    # Fallback usando ping si no hay Scapy
                    devices = []
                    with ThreadPoolExecutor(max_workers=50) as executor:
                        futures = {}
                        for ip in network.hosts():
                            if str(ip).endswith('.1'):  # Probablemente el router
                                futures[executor.submit(self.ping_host, str(ip))] = str(ip)
                        
                        for future in futures:
                            ip = futures[future]
                            if future.result():
                                device = {
                                    'ip': ip,
                                    'mac': 'N/A',
                                    'vendor': 'N/A',
                                    'hostname': resolve_ip(ip),
                                    'status': 'Activo',
                                    'response_time': 'N/A'
                                }
                                devices.append(device)
                    
                    self.window.after(0, self.update_devices_table, devices)
                    
            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("Error de Escaneo", 
                                                                f"Error al escanear la red: {str(e)}"))
            finally:
                self.window.after(0, lambda: self.scan_button.config(state=tk.NORMAL, text="🔍 Escanear Red"))
        
        # Ejecutar escaneo en hilo separado
        scan_thread = threading.Thread(target=scan_worker, daemon=True)
        scan_thread.start()

    def update_devices_table(self, devices):
        """Actualiza la tabla de dispositivos con los resultados del escaneo"""
        self.network_devices = devices
        
        for device in devices:
            self.devices_tree.insert('', 'end', values=(
                device['ip'],
                device['mac'],
                device['vendor'],
                device['hostname'],
                device['status'],
                device['response_time']
            ))
        
        messagebox.showinfo("Escaneo Completado", 
                           f"Se encontraron {len(devices)} dispositivos en la red")

    def export_table_to_csv(self):
        """Exporta solo los datos de la tabla a CSV"""
        if not self.table_data:
            messagebox.showinfo("Sin Datos", "No hay datos en la tabla para exportar")
            return
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"trafico_tabla_{timestamp}.csv"
            
            with open(filename, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Escribir encabezados
                writer.writerow(["Tiempo", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Comentario"])
                # Escribir datos de la tabla
                for row in self.table_data:
                    writer.writerow(row)
            
            messagebox.showinfo("Exportación Exitosa", 
                               f"Datos exportados a: {filename}")
        except Exception as e:
            messagebox.showerror("Error de Exportación", 
                               f"Error al exportar: {str(e)}")

    def analyze_traffic(self):
        def packet_callback(packet):
            if IP in packet and self.monitoring_active:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)

                if TCP in packet:
                    proto_name = "TCP"
                    port = packet[TCP].dport
                elif UDP in packet:
                    proto_name = "UDP"
                    port = packet[UDP].dport
                elif ICMP in packet:
                    proto_name = "ICMP"
                    port = "-"
                else:
                    proto_name = str(proto)
                    port = "-"

                domain = resolve_ip(ip_dst)
                timestamp = datetime.now().strftime('%H:%M:%S')
                comment = f"▶ Conectando a {domain}"

                # Incrementar contador
                self.connection_count += 1

                # Preparar datos para la tabla
                table_row = (timestamp, ip_src, ip_dst, domain, proto_name, port, size, comment)
                
                # Agregar a la lista de datos de tabla
                self.table_data.append(table_row)

                # Mostrar en la tabla - ahora incluye la columna dominio
                self.window.after(0, lambda: self.traffic_tree.insert('', 'end', values=table_row))

                # Actualizar contador en la interfaz
                self.window.after(0, lambda: self.update_status("Analizando", self.connection_count))

                # Ya no guardamos automáticamente en CSV - solo en memoria
                # El usuario puede exportar cuando quiera con el botón "Exportar CSV"

        try:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.monitoring_active)
        except Exception as e:
            self.window.after(0, lambda: messagebox.showerror("Error de Captura", 
                                                              f"Error al capturar paquetes: {str(e)}\n\nAsegúrate de ejecutar como administrador."))
            self.window.after(0, self.stop_monitoring)

    def open_csv(self):
        try:
            abs_path = os.path.abspath(LOG_FILE)
            if os.path.exists(abs_path):
                # Intentar abrir con el programa predeterminado
                if sys.platform.startswith('win'):
                    os.startfile(abs_path)
                elif sys.platform.startswith('darwin'):
                    subprocess.run(['open', abs_path])
                else:
                    subprocess.run(['xdg-open', abs_path])
            else:
                messagebox.showinfo("Información", "El archivo CSV aún no existe. Inicia el análisis para crear datos.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el archivo CSV: {str(e)}")

    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.close_application)
        self.window.mainloop()

    def close_application(self):
        if self.monitoring_active:
            self.stop_monitoring()
        self.window.destroy()

if __name__ == "__main__":
    analyzer = NetworkAnalyzer()
    analyzer.run()