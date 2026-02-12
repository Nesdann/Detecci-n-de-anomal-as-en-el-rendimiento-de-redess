import pandas as pd
import numpy as np
import joblib
import time
import os
import socket
import struct


print("Cargando cerebro de la IA...")
# Carga del modelo
model = joblib.load('ids_neural_model.joblib')
scaler = joblib.load('scaler.pkl')
le = joblib.load('label_encoder.pkl')

features = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp', 'avg_pkt', 'intensity']

def ip_to_str(ip_decimal):
    """Convierte IPs en formato decimal a formato legible"""
    try:
        return socket.inet_ntoa(struct.pack('!L', int(ip_decimal)))
    except:
        return str(ip_decimal)

def guardar_en_reporte(resultado, confianza, datos, ip_src, ip_dst):
    """Guarda cada evento sospechoso en el archivo de reporte histórico"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    ruta_reporte = '/Users/jofreivaan_02/Desktop/python/script/reporte_seguridad.txt'
    
    with open(ruta_reporte, 'a') as f:
        f.write(f"\n[{timestamp}]  ALERTA \n")
        f.write(f"Tipo: {resultado} ({confianza:.2f}% de confianza)\n")
        f.write(f"Origen: {ip_to_str(ip_src)} -> Destino: {ip_to_str(ip_dst)}\n")
        f.write(f"Detalles: {int(datos['packets'])} pkts, {int(datos['bytes'])} bytes, Proto: {int(datos['proto'])}\n")
        f.write("-" * 40 + "\n")

def predecir_flujo(datos_crudos):
    df_nuevo = pd.DataFrame([datos_crudos])
    
    # Cálculo de features inteligentes para detectar SCAN/FLOOD
    df_nuevo['avg_pkt'] = df_nuevo['bytes'] / df_nuevo['packets'].replace(0, 1)
    df_nuevo['intensity'] = df_nuevo['pps'] * df_nuevo['bps']
    
    X_nuevo = df_nuevo[features]
    X_scaled = scaler.transform(X_nuevo)
    
    pred_prob = model.predict(X_scaled, verbose=0)
    clase_idx = np.argmax(pred_prob)
    confianza = np.max(pred_prob) * 100
    
    return le.classes_[clase_idx], confianza

# 2. Función de monitoreo en tiempo real
def monitorear_archivo(ruta_al_archivo):
    print(f"IDS: Vigilando tráfico compartido en: {ruta_al_archivo}")
    
    if not os.path.exists(ruta_al_archivo):
        print(f"Error: El archivo {ruta_al_archivo} no existe.")
        return

    with open(ruta_al_archivo, 'r') as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(0.5) 
                continue
            
            partes = linea.strip().split(',')
            if len(partes) < 9: 
                continue 
            
            try:
                # Extraemos las IPs para el reporte
                ip_src_raw = partes[0]
                ip_dst_raw = partes[1]

                # Mapeamos los datos para la IA
                datos = {
                    'proto': float(partes[2]), 
                    'duration': float(partes[3]),
                    'packets': float(partes[4]), 
                    'bytes': float(partes[5]),
                    'pps': float(partes[6]), 
                    'bps': float(partes[7]),
                    'bpp': float(partes[8])
                }
                
                resultado, score = predecir_flujo(datos)
                
                if resultado != 'NORMAL' and score > 80:
                    print(f" ALERTA: {resultado} ({score:.2f}%)")
                    # Guardamos automáticamente en el .txt
                    guardar_en_reporte(resultado, score, datos, ip_src_raw, ip_dst_raw)
                else:
                    print(f"✅ Tráfico Normal ({score:.2f}%)")

            except Exception as e:
                continue

# --- EJECUCIÓN ---
ruta_compartida = '/Users/jofreivaan_02/Desktop/python/capture/flows.csv'
monitorear_archivo(ruta_compartida)