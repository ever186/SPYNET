# ==============================================================================
# SPYNET V3.0 - EDICIÓN ANALISTA (con instalador de dependencias V2.1 integrado)
# Añade panel de detalles, filtrado en tiempo real y GeoIP.
# ==============================================================================

# --- IMPORTS ---
import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, font, Toplevel, Text
import threading
import time
from datetime import datetime
import subprocess
import csv
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import platform
import importlib.util
from io import StringIO

# ==============================================================================
# SECCIÓN 1: VERIFICADOR E INSTALADOR DE DEPENDENCIAS (Tomado de SPYNET V2.1)
# Esta parte se ejecuta primero para asegurar que todas las herramientas estén listas.
# ==============================================================================

def start_main_application():
    """
    Función que se encarga de instanciar y ejecutar la ventana principal de SPYNET.
    """
    # Verifica si se ejecuta con privilegios de administrador, necesarios para scapy.
    try:
        is_admin = False
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserIsAdmin() # Corregido: IsUserAdmin
        else:
            is_admin = (os.geteuid() == 0)

        if not is_admin:
            messagebox.showwarning("Permisos Insuficientes",
                                 "Se recomienda ejecutar como administrador (o con 'sudo') para una captura completa.")
    except Exception as e:
        print(f"No se pudo verificar los permisos: {e}")

    # Lanza la aplicación principal (la clase NetworkAnalyzer está definida más abajo)
    app = NetworkAnalyzer()
    app.run()

def show_installer_window(packages_to_install):
    """
    Crea una ventana de Tkinter para mostrar el proceso de instalación
    de los paquetes que falten.
    """
    installer_window = tk.Tk()
    installer_window.title("SPYNET - Verificador de Herramientas")
    installer_window.geometry("550x400")
    installer_window.resizable(False, False)
    installer_window.configure(bg="#2c3e50")

    # Título de la ventana
    title_font = font.Font(family="Segoe UI", size=16, weight="bold")
    tk.Label(installer_window, text="Instalando dependencias...", font=title_font, fg="#ecf0f1", bg="#2c3e50").pack(pady=20)

    # Área de texto para mostrar el progreso
    log_frame = tk.Frame(installer_window, bg="#34495e", padx=5, pady=5)
    log_frame.pack(pady=10, padx=20, fill="both", expand=True)
    log_text = tk.Text(log_frame, bg="#34495e", fg="#bdc3c7", relief="flat", height=10, font=("Consolas", 10), bd=0)
    log_text.pack(fill="both", expand=True, padx=1, pady=1)

    # Barra de progreso
    progress = ttk.Progressbar(installer_window, orient="horizontal", length=510, mode="determinate")
    progress.pack(pady=(0, 20), padx=20)

    def update_log(message):
        # Función segura para actualizar la GUI desde un hilo
        installer_window.after(0, lambda: log_text.insert(tk.END, message + "\n"))
        installer_window.after(0, lambda: log_text.see(tk.END))

    def installation_worker():
        # Esta función corre en un hilo separado para no congelar la GUI
        progress_step = 100 / len(packages_to_install)
        all_successful = True

        for i, package_name in enumerate(packages_to_install):
            update_log(f"[*] Buscando '{package_name}'... No encontrado.")
            update_log(f"    -> Intentando instalar automáticamente...")

            try:
                # Se usa sys.executable para garantizar que se use el pip del entorno correcto
                # El comando se ejecuta de forma silenciosa (--quiet)
                command = [sys.executable, "-m", "pip", "install", package_name, "--quiet", "--disable-pip-version-check"]
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

                subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', creationflags=creationflags)
                update_log(f"    -> '{package_name}' instalado correctamente.")
            except Exception as e:
                all_successful = False
                update_log(f"[ERROR] Falló la instalación de '{package_name}'.")
                update_log(f"    -> Razón: {e}. Por favor, verifica tu conexión a internet o intenta instalarlo manualmente.")
                break  # Detiene la instalación si un paquete falla

            installer_window.after(0, lambda p=progress_step * (i + 1): progress.config(value=p))

        if all_successful:
            update_log("\n[+] ¡Todas las herramientas están listas!")
            update_log("    Iniciando SPYNET 3.0...")
            installer_window.after(2000, installer_window.destroy) # Cierra la ventana tras 2 segundos
        else:
            update_log("\n[!] No se pudieron instalar todas las dependencias.")
            update_log("    Por favor, abre una terminal (CMD) y ejecuta 'pip install <paquete>' para los paquetes fallidos.")
            close_button = tk.Button(installer_window, text="Cerrar", command=installer_window.destroy, bg="#e74c3c", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
            installer_window.after(0, lambda: close_button.pack(pady=10))

    # Inicia el hilo de instalación después de que la ventana se haya dibujado
    installer_window.after(250, lambda: threading.Thread(target=installation_worker, daemon=True).start())
    installer_window.mainloop()


def resolve_ip(ip_address):
    try: return socket.gethostbyaddr(ip_address)[0]
    except Exception: return ip_address

class NetworkAnalyzer:
    def __init__(self):
        # --- Importaciones dinámicas ---
        # Estas importaciones se intentan DESPUÉS de que el instalador haya verificado/instalado
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp
        from PIL import Image, ImageTk
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        import matplotlib.dates as mdates
        try:
            import maxminddb
            self.GEOIP_AVAILABLE = True
        except ImportError:
            self.GEOIP_AVAILABLE = False # Se mantendrá en False si maxminddb no se instaló/encontró

        # --- Asignaciones a self ---
        self.scapy_sniff, self.scapy_IP, self.scapy_TCP, self.scapy_UDP, self.scapy_ICMP = sniff, IP, TCP, UDP, ICMP
        self.scapy_ARP, self.scapy_Ether, self.scapy_srp = ARP, Ether, srp
        self.Image, self.ImageTk = Image, ImageTk
        self.Figure, self.FigureCanvasTkAgg, self.mdates = Figure, FigureCanvasTkAgg, mdates
        
        # --- Configuración de la Ventana ---
        self.window = tk.Tk(); self.window.title("SPYNET V3.0"); self.window.geometry("1600x900"); self.window.configure(bg='#2c3e50')
        try:
            # Aquí se busca el ícono de la V3
            icon_path = os.path.join('icons', 'telarana.png') 
            if os.path.exists(icon_path):
                self.window.iconphoto(True, self.ImageTk.PhotoImage(file=icon_path))
            else:
                print(f"Advertencia: Ícono '{icon_path}' no encontrado.")
        except Exception as e: 
            print(f"Error al cargar ícono de la ventana: {e}")
        
        # --- Atributos de Estado ---
        self.monitoring_active = False; self.analysis_thread = None; self.connection_count = 0
        self.all_packets_data = [] # NUEVO: Almacena todos los paquetes, sin filtrar
        self.filter_var = tk.StringVar() # NUEVO: Variable para el campo de filtro
        self.filter_var.trace("w", self.apply_filter) # NUEVO: Llama a apply_filter cada vez que el texto cambia

        # --- Atributos de Gráfico y GeoIP ---
        self.plot_timestamps, self.plot_data, self.graph_update_job = [], [], None
        self.INSECURE_PORTS = {80, 21, 23, 25, 110}
        self.geoip_reader = self.load_geoip_database()

        self.setup_interface()

    # NUEVO: Carga la base de datos GeoIP
    def load_geoip_database(self):
        if not self.GEOIP_AVAILABLE: return None
        try:
            db_path = os.path.join('geoip', 'GeoLite2-City.mmdb')
            return maxminddb.open_database(db_path)
        except FileNotFoundError:
            print("ADVERTENCIA: Archivo GeoLite2-City.mmdb no encontrado en la carpeta 'geoip'. La geolocalización estará desactivada.")
            return None
        except Exception as e:
            print(f"Error al cargar la base de datos GeoIP: {e}")
            return None

    # NUEVO: Obtiene la info de GeoIP para una IP
    def get_geoip_info(self, ip):
        if not self.geoip_reader or ipaddress.ip_address(ip).is_private:
            return "Local/Privada"
        try:
            record = self.geoip_reader.get(ip)
            if record and 'country' in record and 'iso_code' in record['country']:
                return record['country']['iso_code']
            return "N/A"
        except Exception:
            return "Error"

    def setup_interface(self):
        main_container = tk.Frame(self.window, bg='#2c3e50'); main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        control_panel = tk.Frame(main_container, bg='#2c3e50'); control_panel.pack(fill=tk.X, side=tk.TOP, pady=(0, 10))
        #tk.Label(control_panel, text="SPYNET V3.0", font=("Segoe UI", 16, "bold"), bg='#2c3e50', fg='#ecf0f1').pack(side=tk.LEFT, padx=(5, 20))

        try:
            self.icons = {
                "start": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'start.png')).resize((24, 24))),
                "stop": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'stop.png')).resize((24, 24))),
                "clear": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'clear.png')).resize((24, 24))),
                "csv": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'csv.png')).resize((24, 24))),
                "scan": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'scan.png')).resize((24, 24))),
                "export": self.ImageTk.PhotoImage(self.Image.open(os.path.join('icons', 'export.png')).resize((24, 24)))
            }
        except Exception as e:
            messagebox.showerror("Error de Iconos", f"No se pudieron cargar los iconos desde la carpeta 'icons'. Asegúrate de que existan.\nError: {e}")
            self.icons = {}

        self.start_button = tk.Button(control_panel, image=self.icons.get("start"), command=self.start_monitoring, bg='#2c3e50', relief=tk.FLAT, borderwidth=0)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(control_panel, image=self.icons.get("stop"), command=self.stop_monitoring, bg='#2c3e50', relief=tk.FLAT, borderwidth=0, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = tk.Button(control_panel, image=self.icons.get("clear"), command=self.clear_data, bg='#2c3e50', relief=tk.FLAT, borderwidth=0)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        self.open_csv_button = tk.Button(control_panel, image=self.icons.get("csv"), command=self.open_csv, bg='#2c3e50', relief=tk.FLAT, borderwidth=0)
        self.open_csv_button.pack(side=tk.LEFT, padx=(20, 5))
        self.export_button = tk.Button(control_panel, image=self.icons.get("export"), command=self.export_table_to_csv, bg='#2c3e50', relief=tk.FLAT, borderwidth=0)
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.scan_button = tk.Button(control_panel, image=self.icons.get("scan"), command=self.scan_network, bg='#2c3e50', relief=tk.FLAT, borderwidth=0)
        self.scan_button.pack(side=tk.LEFT, padx=(20, 5))
        self.status_info = tk.Label(control_panel, text="Estado: Detenido | Conexiones: 0", font=("Segoe UI", 10), bg='#2c3e50', fg='#bdc3c7')
        self.status_info.pack(side=tk.RIGHT, padx=10)

        # NUEVO: Barra de Filtro
        filter_frame = tk.Frame(main_container, bg='#34495e')
        filter_frame.pack(fill=tk.X, pady=(5, 10))
        tk.Label(filter_frame, text="🔍 Filtro:", font=("Segoe UI", 10, "bold"), fg="#ecf0f1", bg="#34495e").pack(side=tk.LEFT, padx=(10, 5))
        filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var, bg="#2c3e50", fg="white", insertbackground="white", relief=tk.FLAT, font=("Segoe UI", 10), width=100)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        notebook = ttk.Notebook(main_container); notebook.pack(fill=tk.BOTH, expand=True)
        self.traffic_frame = tk.Frame(notebook, bg='#ffffff')
        self.devices_frame = tk.Frame(notebook, bg='#ffffff')
        self.visualization_frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.traffic_frame, text="📊 Análisis de Tráfico")
        notebook.add(self.devices_frame, text="🌐 Dispositivos en Red")
        notebook.add(self.visualization_frame, text="📈 Visualización")

        self.setup_traffic_table()
        self.setup_devices_table()
        self.setup_visualization_tab()

    # MODIFICADO: Se añade la columna GeoIP
    def setup_traffic_table(self):
        frame = tk.Frame(self.traffic_frame, bg='#ffffff'); frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # NUEVO: Añadida la columna "País (IP Origen)"
        cols = ("Tiempo", "País", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Detalles")
        self.traffic_tree = ttk.Treeview(frame, columns=cols, show="headings")
        
        for col in cols: self.traffic_tree.heading(col, text=col)
        self.traffic_tree.column("Tiempo", width=80, anchor='center'); self.traffic_tree.column("País", width=60, anchor='center'); self.traffic_tree.column("Origen", width=120); self.traffic_tree.column("Destino", width=120); self.traffic_tree.column("Dominio", width=200); self.traffic_tree.column("Protocolo", width=80, anchor='center'); self.traffic_tree.column("Puerto", width=60, anchor='center'); self.traffic_tree.column("Tamaño", width=80, anchor='center'); self.traffic_tree.column("Detalles", width=300)
        
        self.traffic_tree.tag_configure('insecure', background='#e74c3c', foreground='white')
        
        # NUEVO: Evento de doble clic para mostrar detalles
        self.traffic_tree.bind("<Double-1>", self.show_packet_details)

        v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.traffic_tree.yview); self.traffic_tree.configure(yscrollcommand=v_scrollbar.set); v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.traffic_tree.xview); self.traffic_tree.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.traffic_tree.pack(fill=tk.BOTH, expand=True)

    def setup_devices_table(self):
        frame = tk.Frame(self.devices_frame, bg='#ffffff'); frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(frame, text="💡 Haz clic en el ícono de la lupa para escanear la red", font=("Segoe UI", 10), bg='#ffffff', fg='#7f8c8d').pack(pady=(0, 10))
        device_cols = ("IP", "MAC", "Fabricante", "Nombre del Host", "Estado"); self.devices_tree = ttk.Treeview(frame, columns=device_cols, show="headings", height=15)
        for col in device_cols: self.devices_tree.heading(col, text=col)
        self.devices_tree.column("IP", width=120); self.devices_tree.column("MAC", width=140); self.devices_tree.column("Fabricante", width=150); self.devices_tree.column("Nombre del Host", width=200); self.devices_tree.column("Estado", width=80, anchor='center')
        d_v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.devices_tree.yview); d_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.devices_tree.pack(fill=tk.BOTH, expand=True)

    def setup_visualization_tab(self):
        self.fig = self.Figure(figsize=(12, 6), dpi=100, facecolor='#ffffff')
        self.ax = self.fig.add_subplot(111); self.ax.set_facecolor('#ecf0f1'); self.ax.set_xlabel("Tiempo", fontsize=10); self.ax.set_ylabel("Tráfico (KB/s)", fontsize=10); self.ax.grid(True, linestyle='--', alpha=0.6)
        self.canvas = self.FigureCanvasTkAgg(self.fig, master=self.visualization_frame)
        self.canvas.draw(); self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True); self.fig.tight_layout()

    # NUEVO: Función para mostrar la ventana de detalles del paquete
    def show_packet_details(self, event):
        item_id = self.traffic_tree.focus()
        if not item_id: return

        item_index = self.traffic_tree.index(item_id)
        
        # Para obtener el paquete correcto, debemos buscar en la lista filtrada actualmente visible
        filter_text = self.filter_var.get().lower()
        if filter_text:
            visible_packets = [p for p in self.all_packets_data if filter_text in ' '.join(map(str, p['values'])).lower()]
            if item_index < len(visible_packets):
                packet_obj = visible_packets[item_index]['packet']
            else: return # Índice fuera de rango
        else:
            packet_obj = self.all_packets_data[item_index]['packet']

        # Crear una nueva ventana
        details_window = Toplevel(self.window)
        details_window.title("Detalles del Paquete")
        details_window.geometry("800x600")
        details_window.configure(bg="#2c3e50")
        
        text_area = Text(details_window, bg="#2c3e50", fg="white", font=("Consolas", 10), wrap="word")
        text_area.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Redirigir stdout para capturar la salida de packet.show()
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        packet_obj.show()
        sys.stdout = old_stdout # Restaurar stdout
        
        packet_details_str = captured_output.getvalue()
        text_area.insert("1.0", packet_details_str)
        text_area.config(state="disabled")

    # NUEVO: Función para aplicar el filtro a la tabla
    def apply_filter(self, *args):
        filter_text = self.filter_var.get().lower()
        
        # Limpiar la tabla actual
        for i in self.traffic_tree.get_children():
            self.traffic_tree.delete(i)
        
        # Repoblar la tabla con los datos que coinciden con el filtro
        for packet_data in self.all_packets_data:
            # El filtro busca en todos los valores de la fila
            if filter_text in ' '.join(map(str, packet_data['values'])).lower():
                self.traffic_tree.insert('', 'end', values=packet_data['values'], tags=packet_data['tags'])

    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True; self.connection_count = 0; self.start_button.config(state=tk.DISABLED); self.stop_button.config(state=tk.NORMAL)
            self.update_status("Analizando", 0)
            self.traffic_thread = threading.Thread(target=self.analyze_traffic, daemon=True); self.traffic_thread.start()
            self.update_graph()

    def stop_monitoring(self):
        if self.monitoring_active:
            self.monitoring_active = False; self.start_button.config(state=tk.NORMAL); self.stop_button.config(state=tk.DISABLED)
            self.update_status("Detenido", self.connection_count)
            if self.graph_update_job: self.window.after_cancel(self.graph_update_job); self.graph_update_job = None

    # MODIFICADO: Limpia la lista de todos los paquetes y el filtro
    def clear_data(self):
        self.filter_var.set("") # Limpiar el campo de filtro
        for i in self.traffic_tree.get_children(): self.traffic_tree.delete(i)
        self.all_packets_data.clear() # Limpiar la lista maestra
        self.connection_count = 0; self.update_status("Detenido", 0)
        self.plot_timestamps.clear(); self.plot_data.clear()
        self.ax.clear(); self.ax.set_xlabel("Tiempo", fontsize=10); self.ax.set_ylabel("Tráfico (KB/s)", fontsize=10); self.ax.grid(True, linestyle='--', alpha=0.6); self.canvas.draw()

    def update_status(self, status, count):
        self.status_info.config(text=f"Estado: {status} | Conexiones: {count}")

    def get_network_range(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80)); local_ip = s.getsockname()[0]
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except Exception: return "192.168.1.0/24"

    def scan_network(self):
        for i in self.devices_tree.get_children(): self.devices_tree.delete(i)
        def scan_worker():
            try:
                answered_list = self.scapy_srp(self.scapy_Ether(dst="ff:ff:ff:ff:ff:ff")/self.scapy_ARP(pdst=self.get_network_range()), timeout=2, verbose=False)[0]
                devices = [{'ip': r.psrc, 'mac': r.hwsrc, 'vendor': self.get_mac_vendor(r.hwsrc), 'hostname': h if (h := resolve_ip(r.psrc)) != r.psrc else "No resuelto", 'status': 'Activo'} for s, r in answered_list]
                self.window.after(0, self.update_devices_table, devices)
            except Exception as e: self.window.after(0, lambda: messagebox.showerror("Error de Escaneo", f"Error al escanear: {e}\n\nAsegúrate de ejecutar como administrador."))
        threading.Thread(target=scan_worker, daemon=True).start()

    def update_devices_table(self, devices):
        for device in devices: self.devices_tree.insert('', 'end', values=(device['ip'], device['mac'], device['vendor'], device['hostname'], device['status']))
        messagebox.showinfo("Escaneo Completado", f"Se encontraron {len(devices)} dispositivos.")

    def get_mac_vendor(self, mac):
        mac_vendors = {"00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox"}; return mac_vendors.get(mac[:8].lower(), "Desconocido")
        
    def export_table_to_csv(self):
        # Esta función ahora exporta los datos actualmente FILTRADOS y VISIBLES en la tabla
        if not self.traffic_tree.get_children(): return messagebox.showinfo("Sin Datos", "No hay datos en la tabla para exportar.")
        try:
            filename = f"trafico_exportado_{datetime.now():%Y%m%d_%H%M%S}.csv"
            with open(filename, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Encabezados de la tabla V3 (con País)
                writer.writerow(["Tiempo", "País", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Detalles"])
                # Iterar sobre los elementos visibles en el Treeview
                for child_id in self.traffic_tree.get_children():
                    writer.writerow(self.traffic_tree.item(child_id)['values'])
            messagebox.showinfo("Exportación Exitosa", f"Datos exportados a: {filename}")
        except Exception as e: messagebox.showerror("Error de Exportación", f"No se pudo exportar: {e}")

    # MODIFICADO: La lógica de captura ahora guarda el objeto de paquete completo
    def analyze_traffic(self):
        def packet_callback(packet):
            if not self.monitoring_active: return

            if self.scapy_IP in packet:
                ip_src = packet[self.scapy_IP].src
                ip_dst = packet[self.scapy_IP].dst
                size = len(packet)
                
                proto_name, port = "Desconocido", "-";
                if self.scapy_TCP in packet: proto_name, port = "TCP", packet[self.scapy_TCP].dport
                elif self.scapy_UDP in packet: proto_name = "UDP"; port = packet[self.scapy_UDP].dport
                elif self.scapy_ICMP in packet: proto_name = "ICMP"
                
                domain = resolve_ip(ip_dst)
                timestamp = datetime.now()
                comment = f"Conectando a {domain}"
                self.connection_count += 1

                # NUEVO: Obtener info de GeoIP
                country = self.get_geoip_info(ip_src)

                # MODIFICADO: El tuple de valores ahora incluye el país
                table_row = (timestamp.strftime('%H:%M:%S'), country, ip_src, ip_dst, domain, proto_name, port, size, comment)
                
                # MODIFICADO: Guardar el objeto de paquete junto con sus valores y etiquetas
                row_tags = ('insecure',) if port in self.INSECURE_PORTS else ()
                packet_data = {'packet': packet, 'values': table_row, 'tags': row_tags}
                self.all_packets_data.append(packet_data)
                
                # Insertar en la tabla solo si pasa el filtro actual
                filter_text = self.filter_var.get().lower()
                if not filter_text or filter_text in ' '.join(map(str, table_row)).lower():
                    self.window.after(0, lambda r=table_row, t=row_tags: self.traffic_tree.insert('', 'end', values=r, tags=t))
                
                # Actualizar el estado y el gráfico
                self.window.after(0, lambda: self.update_status("Analizando", self.connection_count))
                self.plot_timestamps.append(timestamp)
                self.plot_data.append(size / 1024) # KB/s

        try: 
            self.scapy_sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.monitoring_active)
        except Exception as e:
            if "Operation not permitted" in str(e) or "Permission denied" in str(e): 
                self.window.after(0, lambda: messagebox.showerror("Error de Permisos", "Se requieren privilegios de administrador para capturar tráfico.\nIntenta ejecutar el script con 'sudo'."))
            else: 
                self.window.after(0, lambda: messagebox.showerror("Error de Captura", f"Error al capturar paquetes: {e}"))
            self.window.after(0, self.stop_monitoring)
    
    def update_graph(self):
        if not self.monitoring_active: return
        self.ax.clear()
        if self.plot_timestamps:
            max_points = 300; current_time = datetime.now(); data_per_second = {}
            for i in range(len(self.plot_timestamps) - 1, -1, -1):
                ts = self.plot_timestamps[i]
                if (current_time - ts).total_seconds() > max_points: break
                sec_timestamp = ts.replace(microsecond=0); data_per_second[sec_timestamp] = data_per_second.get(sec_timestamp, 0) + self.plot_data[i]
            if data_per_second:
                sorted_times = sorted(data_per_second.keys()); sorted_values = [data_per_second[t] for t in sorted_times]
                self.ax.plot(sorted_times, sorted_values, color='#3498db', marker='o', linestyle='-', markersize=3)
                self.ax.fill_between(sorted_times, sorted_values, color='#3498db', alpha=0.2)
        self.ax.xaxis.set_major_formatter(self.mdates.DateFormatter('%H:%M:%S')); self.ax.tick_params(axis='x', rotation=30, labelsize=8); self.ax.set_xlabel("Tiempo", fontsize=10); self.ax.set_ylabel("Tráfico (KB/s)", fontsize=10); self.ax.grid(True, linestyle='--', alpha=0.6); self.fig.tight_layout()
        self.canvas.draw()
        self.graph_update_job = self.window.after(1000, self.update_graph)

    def open_csv(self):
        # Esta función intentaría abrir un archivo llamado trafico_red.csv,
        # pero la V3 ya no lo usa para guardar todos los paquetes, sino all_packets_data.
        # Por consistencia, podríamos cambiar esta función para abrir el archivo
        # exportado por export_table_to_csv si existe, o indicar que no hay un log persistente.
        # Por ahora, se mantiene la lógica original de V2.
        try:
            # Aquí podrías ajustar para abrir un archivo exportado previamente si lo guardaste con un nombre fijo,
            # o dejarlo así para abrir el CSV generado por V2 si existiera.
            # Para V3, la exportación es más dinámica.
            messagebox.showinfo("Información", "La V3 no guarda un único archivo CSV de log automático. Usa el botón 'Exportar a CSV' para guardar los datos actuales.")
        except Exception as e: messagebox.showerror("Error", f"No se pudo abrir el archivo CSV: {e}")

    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.close_application)
        self.window.mainloop()

    def close_application(self):
        self.stop_monitoring()
        self.window.destroy()

# ==============================================================================
# SECCIÓN DE EJECUCIÓN PRINCIPAL
# Este bloque decide si mostrar el instalador o iniciar la app directamente.
# ==============================================================================

if __name__ == "__main__":
    # Diccionario que mapea el nombre de importación con el nombre del paquete en PyPI
    required_packages = {
        'scapy': 'scapy',
        'psutil': 'psutil',
        'matplotlib': 'matplotlib',
        'PIL': 'Pillow',  # El módulo se llama PIL, pero el paquete es Pillow
        'maxminddb': 'maxminddb' # Añadido para SPYNET V3
    }

    missing_packages = []
    # Primera verificación: ¿falta algo?
    for module_name, package_name in required_packages.items():
        if importlib.util.find_spec(module_name) is None:
            missing_packages.append(package_name)

    if missing_packages:
        # Si faltan paquetes, muestra la ventana de instalación
        show_installer_window(missing_packages)
        
        # Segunda verificación: después del instalador, ¿sigue faltando algo?
        final_missing = []
        for module_name, package_name in required_packages.items():
            if importlib.util.find_spec(module_name) is None:
                final_missing.append(package_name)

        if not final_missing:
            # Si ya no falta nada, inicia la aplicación
            start_main_application()
        else:
            # Si el instalador falló, muestra un error crítico y cierra
            root = tk.Tk(); root.withdraw() # Crea una ventana raíz oculta para el messagebox
            messagebox.showerror("Error Crítico", "No se pudieron instalar todas las dependencias. La aplicación no puede continuar.")
            root.destroy()
    else:
        # Si todo estaba instalado desde el principio, inicia la aplicación directamente
        start_main_application()
