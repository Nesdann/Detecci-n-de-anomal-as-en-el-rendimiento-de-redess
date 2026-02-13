import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score

# --- CONFIGURACIÓN Y RUTAS ---
FILE_PATH = '../capture/test.csv'  
MODEL_NAME = 'ids_neural_model.joblib' 
SCALER_NAME = 'scaler.pkl'
ENCODER_NAME = 'label_encoder.pkl'
FEATURES = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp', 'avg_pkt', 'intensity']

# condiciones
def etiquetar_trafico(row):
    """Reglas  para clasificar el tráfico """
    # SCAN: pocos paquetes y poco peso
    if row['packets'] < 5 and row['avg_pkt'] < 100:
        return 'SCAN'
    # FLOOD: alta intensidad y muchos bytes
    if row['pps'] > 10 and row['bytes'] > 500000:
        return 'FLOOD'
    return 'NORMAL'

#  ENTRENAMIENTO
def ejecutar_entrenamiento():
    print(" Fusionando archivos para máxima precisión...")
    archivos = [
        '../iforestmodel/train_attack.csv', 
        '../iforestmodel/train_normal.csv',
        '../capture/test.csv'
    ]
    
    lista_df = []
    columnas_raw = ['src_ip', 'dst_ip', 'proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp']
    
    for f in archivos:
        if os.path.exists(f):
        
            temp_df = pd.read_csv(f, header=None, names=columnas_raw, on_bad_lines='skip', low_memory=False)
            lista_df.append(temp_df)
    
    df = pd.concat(lista_df, ignore_index=True)

    # Convertimos las columnas numéricas 
    columnas_numericas = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp']
    for col in columnas_numericas:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Eliminamos cualquier fila que haya quedado con NaNs 
    df = df.dropna()
    print(f"Dataset limpio: {len(df)} registros listos para procesar.")
    
    
    # Feature 
    df['avg_pkt'] = df['bytes'] / df['packets'].replace(0, 1)
    df['intensity'] = df['pps'] * df['bps']
    df['etiqueta_esperada'] = df.apply(etiquetar_trafico, axis=1)

    # Preparación de datos
    X = df[FEATURES]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    le = LabelEncoder()
    y = le.fit_transform(df['etiqueta_esperada'])

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    
    print("Entrenando Red Neuronal (MLP)...")
    mlp = MLPClassifier(
        hidden_layer_sizes=(32, 16), 
        max_iter=1000, 
        activation='relu', 
        solver='adam', 
        random_state=42
    )
    
    mlp.fit(X_train, y_train)

    print(f"Precisión en entrenamiento: {mlp.score(X_train, y_train) * 100:.2f}%")
    print(f"Precisión en test: {mlp.score(X_test, y_test) * 100:.2f}%")

    # Verificación de Precisión
    y_pred = mlp.predict(X_test)
    precision = accuracy_score(y_test, y_pred) * 100
    print(f"Precisión final: {precision:.2f}%")

    # Guardar Artefactos
    joblib.dump(mlp, MODEL_NAME)
    joblib.dump(scaler, SCALER_NAME)
    joblib.dump(le, ENCODER_NAME)
    print(f" neurona exportado con éxito como {MODEL_NAME}")

if __name__ == "__main__":
    ejecutar_entrenamiento()