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
    print(" Entrenando Isolation Forest para detección explicativa...")
    
    
    
    archivos = [
        '../capture/train_normal.csv', 
        'train_normal.csv', 
        './train_normal.csv',
        '../iforestmodel/train_normal.csv'
    ]
    lista_df = []
    columnas_raw = [
    "src_ip","dst_ip","src_port","dst_port","proto",
    "fwd_pkts","bwd_pkts","fwd_bytes","bwd_bytes",
    "packets","bytes",
    "syn_count","ack_count","fin_count","rst_count",
    "syn_ratio","rst_ratio","ack_ratio",
    "duration","pps","bps",
    "dir_ratio","byte_ratio","avg_pkt",
    "std_iat","idle_ratio","is_short_flow",
    "packet_imbalance","byte_imbalance","flag_density","syn_minus_ack","log_pps","log_bps"
]
    
    for f in archivos:
        if os.path.exists(f):
            print(f"📁 Leyendo archivo: {f}")
            temp_df = pd.read_csv(f, header=None, names=columnas_raw, on_bad_lines='skip', low_memory=False)
            print(f"   -> Encontradas {len(temp_df)} filas.")
            lista_df.append(temp_df)
        else:
            print(f"⚠️ Archivo no encontrado: {f}")
    
    if not lista_df:
        print(" ERROR : No se encontró ningún archivo con datos. El entrenamiento no puede empezar.")
        return

    df = pd.concat(lista_df, ignore_index=True)
    
    
    columnas_numericas = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'avg_pkt']
    for col in columnas_numericas:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Limpieza de valores nulos o infinitos
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
    
    print(f"✅ Total de filas válidas tras limpieza: {len(df)}")

    if len(df) == 0:
        print(" ERROR: Después de limpiar los datos, quedaron 0 filas. Revisa el formato de tus CSV.")
        return

    #
    df['bpp'] = df['bytes'] / df['packets'].replace(0, 1)
    df['intensity'] = df['pps'] * df['bps']

    X = df[FEATURES]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X) 

    model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
    model.fit(X_scaled)

    joblib.dump(model, MODEL_NAME)
    joblib.dump(scaler, SCALER_NAME)
    print(f"🚀 ¡Modelo guardado con éxito! ({len(df)} muestras procesadas)")