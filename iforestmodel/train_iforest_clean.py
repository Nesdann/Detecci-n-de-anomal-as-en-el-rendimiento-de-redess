import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

# --------------------------------------------------
# CARGA
# --------------------------------------------------

X_full = pd.read_csv("train_normal_limpio.csv")
test_df = pd.read_csv("test_mixed_limpio.csv")

y_test = test_df["label"]
X_test = test_df.drop(columns=["label"])

print("Train total normales:", len(X_full))
print("Test total:", len(X_test))
print("Distribución test:")
print(y_test.value_counts())
print("-"*50)

# --------------------------------------------------
# SPLIT INTERNO SOLO EN NORMALES
# --------------------------------------------------

X_train, X_val = train_test_split(
    X_full,
    test_size=0.2,
    random_state=42
)

# --------------------------------------------------
# ESCALADO
# --------------------------------------------------

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

# --------------------------------------------------
# MODELO (hiperparámetros razonables, no sobreajuste)
# --------------------------------------------------

model = IsolationForest(
    n_estimators=200,
    max_samples="auto",
    contamination=0.2,
    max_features=0.8,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled)

# --------------------------------------------------
# THRESHOLD BASADO SOLO EN VALIDATION (normales)
# --------------------------------------------------

val_scores = model.decision_function(X_val_scaled)

# Elegimos threshold como percentil bajo de normales
# Esto controla tasa de falsos positivos en normales
threshold = np.percentile(val_scores, 5)

print("Threshold elegido (percentil 5% normales):", threshold)

# --------------------------------------------------
# EVALUACIÓN FINAL EN TEST (una sola vez)
# --------------------------------------------------

test_scores = model.decision_function(X_test_scaled)
y_pred = (test_scores < threshold).astype(int)

print("\nMatriz de confusión:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification report:")
print(classification_report(y_test, y_pred))
