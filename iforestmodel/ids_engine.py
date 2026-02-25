import pandas as pd
import numpy as np
import joblib
import time
import os
import warnings
from config import state 

warnings.filterwarnings("ignore")

# Carga de artefactos de IA
try:
    model = joblib.load('ids_neural_model.joblib')
    scaler = joblib.load('scaler.pkl')
    le = joblib.load('label_encoder.pkl')
    print("✅ Red Neuronal cargada exitosamente.")
except Exception as e:
    print(f"❌ ERROR al cargar el modelo: {e}")

PIPE_PATH = "/tmp/ids_pipe"

def run_engine():
    if not os.path.exists(PIPE_PATH):
        os.mkfifo(PIPE_PATH)

    print(f"🚀 IDS ONLINE | Modo: {state.action_mode} | Vigilando Pipe...")

    while state.running:
        try:
            print("🔍 [DEBUG 1] Intentando abrir el pipe...")
            with open(PIPE_PATH, "r") as fifo:
                print("📖 [DEBUG 2] Pipe abierto, esperando datos del sniffer...")
                for line in fifo:
                    if not state.running: break
                    
                    start_t = time.perf_counter()
                    line_data = line.strip()
                    if not line_data: continue
                    
                    print(f"📩 [DEBUG 3] LÍNEA RECIBIDA: {line_data[:60]}...")
                    parts = line_data.split(',')
                    print(f"📊 [DEBUG 4] Columnas detectadas: {len(parts)}")
                    
                    if len(parts) < 32: 
                        print(f"⚠️ [DEBUG] Línea rechazada por tener solo {len(parts)} columnas")
                        continue 

                    # 1. Identificadores
                    src_ip, dst_ip, src_p, dst_p = parts[0], parts[1], parts[2], parts[3]

                    # 2. Pre-procesamiento
                    try:
                        proto = float(parts[4])
                        duration = float(parts[18])
                        packets = float(parts[9])    
                        bytes_val = float(parts[10])  
                        pps = float(parts[19])
                        bps = float(parts[20])
                        bpp = float(parts[23])        
                        
                        avg_pkt = bpp 
                        intensity = pps * bps
                        
                        features_list = [proto, duration, packets, bytes_val, pps, bps, bpp, avg_pkt, intensity]
                        X_raw = np.array(features_list).reshape(1, -1)
                        
                        # 3. Predicción
                        X_scaled = scaler.transform(X_raw)
                        pred_prob = model.predict_proba(X_scaled)
                        idx = np.argmax(pred_prob[0])
                        
                        resultado = le.classes_[idx] 
                        confianza = pred_prob[0][idx] * 100
                        
                        # 4. Forzar envío al Dashboard para ver que funcione
                        dt = (time.perf_counter() - start_t) * 1000 
                        
                        alerta = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "src_ip": src_ip,
                            "src_p": src_p,
                            "dst_ip": dst_ip,
                            "dst_p": dst_p,
                            "score": round(confianza, 2),
                            "tipo": resultado,
                            "ms": round(dt, 2)
                        }
                        
                        state.last_alerts.append(alerta)
                        if len(state.last_alerts) > 50: 
                            state.last_alerts.pop(0)

                        print(f"🔥 [ALERTA GENERADA] {resultado} de {src_ip} | Dashboard actualizado.")

                    except Exception as e_proc:
                        print(f"❌ Error en procesamiento de IA: {e_proc}")

        except Exception as e:
            print(f"⚠️ Error en el pipe: {e}")
            time.sleep(1)
            continue