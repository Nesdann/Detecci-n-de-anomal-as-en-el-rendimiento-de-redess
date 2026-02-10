import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# =========================
# Cargar datasets
# =========================
train = pd.read_csv("train_normal.csv")
test_normal = pd.read_csv("test_normall.csv")
attack = pd.read_csv("attack.csv")

# Labels reales (solo para evaluar)
y_test = np.concatenate([
    np.ones(len(test_normal)),    # normal = 1
    -np.ones(len(attack))          # ataque = -1
])

X_test = pd.concat([test_normal, attack], ignore_index=True)

# =========================
# Entrenar modelo
# =========================
model = IsolationForest(
    n_estimators=300,
    max_samples="auto",
    contamination=0.2,#ajustable
    random_state=42,
    n_jobs=-1
)

model.fit(train)

# =========================
# Predicción
# =========================
y_pred = model.predict(X_test)

# =========================
# Resultados
# =========================
print("Matriz de confusión:")
print(confusion_matrix(y_test, y_pred))

print("\nReporte:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Ataque", "Normal"]
))

# =========================
# Guardar modelo
# =========================
joblib.dump(model, "iforest_model.joblib")
print("\nModelo guardado como iforest_model.joblib")

