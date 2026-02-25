import pandas as pd
import numpy as np
import joblib
import time
import os
import socket
import struct
import requests


# Carga de archivos
model = joblib.load('ids_neural_model.joblib')
scaler = joblib.load('scaler.pkl')
le = joblib.load('label_encoder.pkl')

features = ['proto', 'duration', 'packets', 'bytes', 'pps', 'bps', 'bpp', 'avg_pkt', 'intensity']

def ip_to_str(ip_decimal):
    try: return socket.inet_ntoa(struct.pack('!L', int(float(ip_decimal))))
    except: return str(ip_decimal)

def enviar_al_dashboard(resultado, score, ip_src, ip_dst):
    payload = {
        "timestamp": time.strftime("%H:%M:%S"),
        "origen": ip_to_str(ip_src),
        "destino": ip_to_str(ip_dst),
        "tipo": resultado,
        "score": round(score, 2)
    }
    try: requests.post("http://localhost:8000/api/alerts", json=payload, timeout=0.5)
    except: pass

def predecir_flujo(datos_crudos):
    df = pd.DataFrame([datos_crudos])
    df['avg_pkt'] = df['bytes'] / df['packets'].replace(0, 1)
    df['intensity'] = df['pps'] * df['bps']
    X_scaled = scaler.transform(df[features])
    pred_prob = model.predict_proba(X_scaled)
    idx = np.argmax(pred_prob[0])
    return le.classes_[idx], pred_prob[0][idx] * 100

def monitorear_archivo(ruta):
    print(f"Vigilando: {ruta}")
    if not os.path.exists(ruta): return
    with open(ruta, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(0.5)
                continue
            try:
                p = linea.strip().split(',')
                if len(p) < 9: continue
                datos = {'proto':float(p[2]), 'duration':float(p[3]), 'packets':float(p[4]), 
                         'bytes':float(p[5]), 'pps':float(p[6]), 'bps':float(p[7]), 'bpp':float(p[8])}
                res, score = predecir_flujo(datos)
                
                enviar_al_dashboard(res, score, p[0], p[1])
                print(f"{res} ({score:.2f}%)")
            except: continue

ruta_csv = '/Users/jofreivaan_02/Desktop/python/capture/flows.csv'
monitorear_archivo(ruta_csv)