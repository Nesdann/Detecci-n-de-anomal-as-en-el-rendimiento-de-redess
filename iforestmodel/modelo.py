import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_NAME = 'iforest_model.joblib' 
SCALER_NAME = 'scaler.pkl'


FEATURES = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp', 'avg_pkt', 'intensity']

def ejecutar_entrenamiento():
    print("🧠 Entrenando IA con tu archivo: train_normal_limpio")
    
    # Ruta al archivo que me pasaste
    archivo = 'train_normal_limpio.csv' 
    
    if not os.path.exists(archivo):
        print(f" Error: No se encuentra el archivo {archivo}")
        return

    
    df = pd.read_csv(archivo)
    
    
    df = df.rename(columns={
        'total_packets': 'packets',
        'total_bytes': 'bytes'
    })
    
    
    if 'proto' not in df.columns:
        df['proto'] = 6 

    
    df['bpp'] = df['bytes'] / df['packets'].replace(0, 1)
    df['intensity'] = df['pps'] * df['bps']

    
    X = df[FEATURES].dropna()
    print(f"📊 Entrenando con {len(X)} muestras de tráfico real...")

    #normalizacion 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_scaled)

    
    joblib.dump(model, MODEL_NAME)
    joblib.dump(scaler, SCALER_NAME)
    print(f" ¡IA Calibrada!")

if __name__ == "__main__":
    ejecutar_entrenamiento()