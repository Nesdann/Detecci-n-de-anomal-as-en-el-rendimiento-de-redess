import pandas as pd
import numpy as np
import joblib
import time
import os

# Cargar el cerebro
model = joblib.load('ids_model.pkl')
scaler = joblib.load('scaler.pkl')
threshold = joblib.load('threshold.pkl')

PIPE_PATH = "/tmp/ids_pipe"
if not os.path.exists(PIPE_PATH):
    os.mkfifo(PIPE_PATH)

print(f"✅ IDS ONLINE | Esperando tráfico... | Threshold: {threshold:.4f}")

try:
    while True:
        with open(PIPE_PATH, "r") as fifo:
            for line in fifo:
                start_t = time.perf_counter()
                
                parts = line.strip().split(',')
                if len(parts) < 30: continue # Seguridad
                
                # 1. Extraer Info de Red
                src_ip, dst_ip, src_p, dst_p = parts[0:4]
                
                # 2. Extraer Features (las 28 que el modelo conoce)
                features = np.array([float(x) for x in parts[4:]]).reshape(1, -1)
                
                # 3. Predicción
                f_scaled = scaler.transform(features)
                score = model.decision_function(f_scaled)[0]
                
                # 4. ¿Es Ataque?
                if score < threshold:
                    dt = (time.perf_counter() - start_t) * 1000
                    print(f"\n🔥 [ALERTA] Anomalía Detectada!")
                    print(f"   Origen : {src_ip}:{src_p}")
                    print(f"   Destino: {dst_ip}:{dst_p}")
                    print(f"   Score  : {score:.4f} | Proceso: {dt:.2f}ms")
                    print("-" * 40)
except KeyboardInterrupt:
    print("\nIDS Detenido por el usuario.")