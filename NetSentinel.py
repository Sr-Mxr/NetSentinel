import subprocess
import os
import signal
import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import rdpcap, IP, TCP, ARP
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import time
import webbrowser

# Estado previo para evitar envíos innecesarios
previous_state = {"report": None, "alerts": None}

def check_tcpdump():
    """Verifica si tcpdump está instalado."""
    try:
        subprocess.run(["tcpdump", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def start_capture(interface="eth0", output_file="capture.pcap", filter_expr=None):
    """Inicia la captura de tráfico con tcpdump en segundo plano."""
    if not check_tcpdump():
        print("Error: tcpdump no está instalado. Instálalo y vuelve a intentarlo.")
        return None
    
    cmd = ["tcpdump", "-i", interface, "-w", output_file, "-q"]
    if filter_expr:
        cmd.extend(["-f", filter_expr])
    
    print(f"[INFO] Iniciando captura en {interface}. Guardando en {output_file}...")
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return process

def stop_capture(process):
    """Detiene la captura de tráfico."""
    if process:
        process.send_signal(signal.SIGINT)
        process.wait()
        print("[INFO] Captura detenida y guardada correctamente.")
    else:
        print("[WARNING] No hay ninguna captura en ejecución.")

def analyze_traffic(pcap_file):
    """Analiza el tráfico capturado en busca de actividad sospechosa."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ERROR] No se pudo leer el archivo pcap: {e}")
        return Counter(), []

    ip_counter = Counter()
    alerts = []
    unique_alerts = set()
    
    for pkt in packets:
        if pkt.haslayer(IP):
            ip_counter[pkt[IP].src] += 1
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].flags == 2:
            alert_msg = f"🔶 Posible escaneo de puertos detectado desde {pkt[IP].src}"
            if alert_msg not in unique_alerts:   
                alerts.append({"tipo": "critico", "mensaje": alert_msg})
                unique_alerts.add(alert_msg)
        
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            alert_msg = f"🚨 Posible ataque ARP Spoofing: {pkt[ARP].psrc} -> {pkt[ARP].hwsrc}"
            if alert_msg not in unique_alerts:
                alerts.append({"tipo": "critico", "mensaje": alert_msg})
                unique_alerts.add(alert_msg)
    
    with open("scan_results.txt", "w") as f:
        f.write("Resultados del escaneo:\n")
        f.write("Top 10 IPs más activas:\n")
        for ip, count in ip_counter.most_common(10):
            f.write(f"{ip}: {count} paquetes\n")
        
        f.write("\nAlertas encontradas:\n")
        for alert in alerts:
            f.write(f"{alert['mensaje']}\n")
    
    return ip_counter, alerts

def generate_report(ip_counter):
    """Genera datos para visualizar en la interfaz web."""
    top_ips = ip_counter.most_common(10)
    return {"ips": [ip for ip, _ in top_ips], "counts": [count for _, count in top_ips]}

# Configuración de Flask con SocketIO
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def get_data():
    ip_counter, alerts = analyze_traffic("capture.pcap")
    report = generate_report(ip_counter)
    return jsonify({"report": report, "alerts": alerts})

def real_time_update():
    """Envía actualizaciones en tiempo real solo si hay cambios."""
    global previous_state
    while True:
        ip_counter, alerts = analyze_traffic("capture.pcap")
        report = generate_report(ip_counter)
        
        if report != previous_state["report"] or alerts != previous_state["alerts"]:
            socketio.emit("update", {"report": report, "alerts": alerts})
            print(f"[ENVÍO] {len(alerts)} alertas enviadas a la web.")
            previous_state["report"] = report
            previous_state["alerts"] = alerts
        
        time.sleep(5)

if __name__ == "__main__":
    interface = input("Ingrese la interfaz de red (por defecto eth0): ") or "eth0"
    output_file = input("Nombre del archivo de captura (por defecto capture.pcap): ") or "capture.pcap"
    print("Expresión de filtro (opcional): (Ejemplo: 'tcp', 'udp', 'port 80')")
    filter_expr = input("Ingrese el filtro (puede dejarlo vacío): ")
    
    flask_thread = threading.Thread(target=lambda: socketio.run(app, debug=True, use_reloader=False))
    flask_thread.daemon = True
    flask_thread.start()
    
    update_thread = threading.Thread(target=real_time_update)
    update_thread.daemon = True
    update_thread.start()
    
    process = start_capture(interface, output_file, filter_expr)
    
    webbrowser.open("http://127.0.0.1:5000")
    
    input("Presiona Enter para detener la captura...")
    stop_capture(process)
    
    print("[INFO] Servidor web disponible en http://127.0.0.1:5000")
