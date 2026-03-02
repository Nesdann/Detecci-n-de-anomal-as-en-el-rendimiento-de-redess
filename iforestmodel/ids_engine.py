import pandas as pd
import numpy as np
import joblib
import time
import os
import warnings
from config import state 
from database import guardar_alerta
from modelo import FEATURES, ejecutar_entrenamiento
import csv

warnings.filterwarnings("ignore")


try:
    
    model = joblib.load('iforest_model.joblib')
    scaler = joblib.load('scaler.pkl')
    FEATURES = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp', 'avg_pkt', 'intensity']
    print("✅ Isolation Forest cargado exitosamente.")
except Exception as e:
    print(f"ERROR al cargar el modelo: {e}")

PIPE_PATH = "../ids_pipe"

def obtener_explicacion(X_scaled, X_raw):
    """ Identifica la variable con mayor desviación estadística """
    pesos = np.abs(X_scaled[0])
    idx_max = np.argmax(pesos)
    feature = FEATURES[idx_max]
    valor = X_raw[0][idx_max]
    
    if feature in ['pps', 'intensity']:
         return f"Flood ({feature}: {valor:.2f})"

    if feature in ['packets', 'avg_pkt'] and valor < 10:
         return "Port Scan"

    if feature == 'bpp': 
        return f"Tamaño sospechoso ({valor:.2f} bpp)"

    return f"Inusual: {feature}"

def recargar_modelo():
    global model, scaler
    try:
        model = joblib.load('iforest_model.joblib')
        scaler = joblib.load('scaler.pkl')
        print("🔄 [SISTEMA] ¡Nueva IA cargada y lista para detectar!")
    except Exception as e:
        print(f"❌ Error recargando modelo: {e}")

def run_engine():
    # Aseguramos que el pipe exista con permisos en Mac
    if not os.path.exists(PIPE_PATH): 
        os.mkfifo(PIPE_PATH)
        os.chmod(PIPE_PATH, 0o777)

    print(f"🚀 IDS ONLINE | Vigilando datos de en0...")

    while state.running:
        try:
            with open(PIPE_PATH, "r") as fifo:
                for line in fifo:
                    if not state.running: break
                    
                    line_data = line.strip()
                    if not line_data or "TEST" in line_data: continue
                    
                    start_t = time.perf_counter()
                    parts = line_data.split(',')
                    
                    
                    if len(parts) < 25: 
                        continue 

                    
                    src_ip = parts[0]
                    dst_ip = parts[1]
                    src_p  = parts[2]
                    dst_p  = parts[3]

                    try:
                        
                        proto     = float(parts[4])
                        duration  = float(parts[18])
                        packets   = float(parts[5])    
                        bytes_val = float(parts[7])  
                        pps       = float(parts[19])
                        bps       = float(parts[20])
                        bpp       = float(parts[23])        
                        avg_pkt   = bpp 
                        intensity = pps * bps
                        
                        features_list = [proto, duration, packets, bytes_val, pps, bps, bpp, avg_pkt, intensity]

                        #calibracion: guardamos el dato para entrenar después
                        if state.is_calibrating:
                            with open('train_normal_limpio.csv', 'a', newline='') as f:
                              writer = csv.writer(f)
                              writer.writerow(features_list)
                            continue # Saltamos la predicción porque estamos aprendiendo

                        X_raw = np.array(features_list).reshape(1, -1)
                        X_scaled = scaler.transform(X_raw)
                        
                        
                        pred = model.predict(X_scaled)[0]
                        
                        # Si es anomalía (-1)
                        if pred == -1:
                            razon = obtener_explicacion(X_scaled, X_raw)
                            dt = (time.perf_counter() - start_t) * 1000 
                            
                            alerta = {
                                "timestamp": time.strftime("%H:%M:%S"),
                                "src_ip": src_ip, "src_p": src_p,
                                "dst_ip": dst_ip, "dst_p": dst_p,
                                "score": 100.0, 
                                "tipo": razon,
                                "ms": round(dt, 2)
                            }
                            
                            state.last_alerts.append(alerta)
                            guardar_alerta(alerta)
                            
                            if len(state.last_alerts) > 50: 
                                state.last_alerts.pop(0)
                            
                            print(f"🔥 [ALERTA] {src_ip} -> {razon} ({round(dt,2)}ms)")

                    except Exception as e_proc:
                        
                        continue

        except Exception as e:
            time.sleep(1)
            continue