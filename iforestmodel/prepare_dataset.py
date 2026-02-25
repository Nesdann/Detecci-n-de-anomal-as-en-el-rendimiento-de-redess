import pandas as pd
import numpy as np

columnas = [
    "src_ip","src_port","dst_ip","dst_port","proto",
    "fwd_packets","bwd_packets","fwd_bytes","bwd_bytes",
    "total_packets","total_bytes",
    "syn_count","ack_count","fin_count","rst_count",
    "syn_ratio","rst_ratio","ack_ratio",
    "duration","pps","bps",
    "dir_ratio","byte_ratio","avg_pkt",
    "std_iat","idle_ratio","is_short_flow",
    "duration_dup","label"
]

# Cargar datasets

test_normal = pd.read_csv("test_normal.csv", header=None, names=columnas)
train_normal = pd.read_csv("train_normal.csv", header=None, names=columnas)
ataque = pd.read_csv("test_ata.csv", header=None, names=columnas)

test_normal["label"] = 0
ataque["label"] = 1

# Función de limpieza

def limpiar(df):

    df = df.drop(columns=[
        "src_ip","dst_ip",
        "src_port","dst_port",
        "proto",
        "duration_dup"
    ])

    df["packet_imbalance"] = abs(df["fwd_packets"] - df["bwd_packets"])
    df["byte_imbalance"] = abs(df["fwd_bytes"] - df["bwd_bytes"])

    df["flag_density"] = (
        df["syn_count"] +
        df["ack_count"] +
        df["fin_count"] +
        df["rst_count"]
    ) / (df["total_packets"] + 1e-6)

    df["syn_minus_ack"] = df["syn_ratio"] - df["ack_ratio"]

    df["log_pps"] = np.log1p(df["pps"])
    df["log_bps"] = np.log1p(df["bps"])

    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    return df

# Limpiar por separado

train_normal_limpio = limpiar(train_normal.copy())
test_normal_limpio = limpiar(test_normal.copy())
ataque_limpio = limpiar(ataque.copy())

# 1️⃣ Dataset SOLO NORMAL para entrenar

train_normal = train_normal_limpio.drop(columns=["label"])
train_normal.to_csv("train_normal_limpio.csv", index=False)

# 2️⃣ Dataset MIXTO para evaluar

test_mixed = pd.concat([test_normal_limpio, ataque_limpio], axis=0)
test_mixed = test_mixed.sample(frac=1, random_state=42).reset_index(drop=True)

test_mixed.to_csv("test_mixed_limpio.csv", index=False)

print("Listo.")
print("Train normal:", len(train_normal))
print("Test mixed:", len(test_mixed))
print("Distribución test:")
print(test_mixed["label"].value_counts())

