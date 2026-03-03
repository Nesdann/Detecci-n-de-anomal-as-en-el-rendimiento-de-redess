import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_NAME = 'iforest_model.joblib' 
SCALER_NAME = 'scaler.pkl'


FEATURES = ['proto', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes', 
    'total_packets', 'total_bytes', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
    'syn_ratio', 'rst_ratio', 'ack_ratio', 'duration', 'pps', 'bps',
    'dir_ratio', 'byte_ratio', 'avg_pkt', 'std_iat', 'idle_ratio', 'is_short_flow',
    'packet_imbalance', 'byte_imbalance', 'flag_density', 'syn_minus_ack', 'log_pps', 'log_bps']

def ejecutar_entrenamiento():
    print("🧠 Entrenando IA con tu archivo: train_normal_limpio")
    
    # Ruta al archivo que me pasaste
    archivo = 'train_normal_limpio.csv' 
    
    if not os.path.exists(archivo):
        print(f" Error: No se encuentra el archivo {archivo}")
        return

    
    df = pd.read_csv(archivo, names=FEATURES)
    



    
    X = df[FEATURES].dropna()
    print(f"📊 Entrenando con {len(X)} muestras de tráfico real...")

    #normalizacion 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_scaled)

    
    joblib.dump(model, MODEL_NAME)
    joblib.dump(scaler, SCALER_NAME)
    print(f" ¡IA Calibrada!29")

if __name__ == "__main__":
    ejecutar_entrenamiento()