import pandas as pd
import numpy as np
import joblib
import time
import os
from config import state  # <Usamos el estado compartido
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

#Cargar
model = joblib.load('ids_model.pkl')
scaler = joblib.load('scaler.pkl')
# Cargamos el inicial
initial_threshold = joblib.load('threshold.pkl')
state.threshold = initial_threshold #state

PIPE_PATH = "/tmp/ids_pipe"

def run_engine():
    if not os.path.exists(PIPE_PATH):
        os.mkfifo(PIPE_PATH)

    print(f"✅ IDS ONLINE | Motor en hilo separado | Threshold Inicial: {state.threshold:.4f}")

    while state.running:
        # Abrimos el FIFO. 
        # Nota: 'with' dentro del loop para que si el sniffer se reinicia, el pipe no se rompa
        with open(PIPE_PATH, "r") as fifo:
            for line in fifo:
                if not state.running: break
                
                start_t = time.perf_counter()
                
                parts = line.strip().split(',')
                if len(parts) < 30: continue 
                
                # 1. Extraer Info de Red
                src_ip, dst_ip, src_p, dst_p = parts[0:4]
                
                # 2. Extraer Features
                features = np.array([float(x) for x in parts[4:]]).reshape(1, -1)
                
                # 3. Predicción
                f_scaled = scaler.transform(features)
                score = model.decision_function(f_scaled)[0]
                
                # 4. ¿Es Ataque? 
                # USAMOS state.threshold (el que la API puede cambiar)
                if score < state.threshold:
                    # Dentro de tu bucle de predicción, cuando score < state.threshold:

                     if src_ip in state.whitelist:
                         continue 

            # Si no está en la whitelist, procesamos la alerta
                     dt = (time.perf_counter() - start_t) * 1000
                     alerta = {"src_ip": src_ip, "score": float(score), "ms": dt}
                     state.last_alerts.append(alerta)


                     state.ban_list[src_ip] = state.ban_list.get(src_ip, 0) + 1

                     if state.action_mode == "block" and state.ban_list[src_ip] >= state.auto_ban_threshold:
                         print(f"🚫 [BLOQUEO] Ejecutando baneo para {src_ip}...")
                 # os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")
                    
                    # Creamos un diccionario con la alerta
                     alerta = {
                        "src_ip": src_ip,
                        "src_p": src_p,
                        "dst_ip": dst_ip,
                        "dst_p": dst_p,
                        "score": round(float(score), 4),
                        "ms": round(dt, 2),
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                    
                    # Guardamos la alerta en el estado global para que la API la vea
                     state.last_alerts.append(alerta)
                    
                    # Limitar historial para no saturar la RAM (opcional)
                     if len(state.last_alerts) > 100:
                        state.last_alerts.pop(0)

                     print(f"🔥 [ALERTA] {src_ip} -> {dst_ip} | Score: {score:.4f}")