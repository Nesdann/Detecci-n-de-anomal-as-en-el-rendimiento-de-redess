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
            with open(PIPE_PATH, "r") as fifo:
                for line in fifo:
                    if not state.running: 
                        break
                    
                    start_t = time.perf_counter()
                    parts = line.strip().split(',')
                    
                    if len(parts) < 32: 
                        continue 

                    # 1. Identificadores para Dashboard
                    src_ip, dst_ip, src_p, dst_p = parts[0], parts[1], parts[2], parts[3]

                    # 2. Pre-procesamiento de Features para Red Neuronal
                    try:
                        proto = float(parts[4])
                        duration = float(parts[18])
                        packets = float(parts[9])    # total_packets
                        bytes_val = float(parts[10])  # total_bytes
                        pps = float(parts[19])
                        bps = float(parts[20])
                        bpp = float(parts[23])        # avg_pkt
                        
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
                        
                        # 4. Lógica de Detección y Respuesta
                        if resultado != 'NORMAL' and src_ip not in state.whitelist:
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

                            # Gestión de baneo dinámico
                            state.ban_list[src_ip] = state.ban_list.get(src_ip, 0) + 1
                            
                            if state.action_mode == "block" and state.ban_list[src_ip] >= state.auto_ban_threshold:
                                print(f"🚫 [BLOQUEO] IP BANNEADA: {src_ip}")

                            print(f"🔥 [ALERTA] {resultado} detectado de {src_ip} | Confianza: {confianza:.2f}%")

                    except ValueError:
                        continue # Salta líneas con datos corruptos o cabeceras

        except Exception as e:
            time.sleep(1) # Recuperación ante cierre de pipe
            continue