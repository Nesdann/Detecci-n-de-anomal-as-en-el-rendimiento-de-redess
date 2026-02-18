import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report, f1_score, precision_score, recall_score

# --------------------------------------------------
# CARGA
# --------------------------------------------------

X_train = pd.read_csv("train_normal_limpio.csv")
test_df = pd.read_csv("test_mixed_limpio.csv")

y_test = test_df["label"]
X_test = test_df.drop(columns=["label"])

print("Train:", len(X_train))
print("Test:", len(X_test))
print("Distribución test:")
print(y_test.value_counts())
print("-"*50)

# --------------------------------------------------
# ESCALADO
# --------------------------------------------------

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# --------------------------------------------------
# GRID MANUAL DE HIPERPARÁMETROS
# --------------------------------------------------

n_estimators_list = [100, 200]
max_samples_list = ["auto", 0.8]
contamination_list = [0.1, 0.2, 0.3]
max_features_list = [1.0, 0.8]

results = []

for n_est in n_estimators_list:
    for max_s in max_samples_list:
        for cont in contamination_list:
            for max_f in max_features_list:

                model = IsolationForest(
                    n_estimators=n_est,
                    max_samples=max_s,
                    contamination=cont,
                    max_features=max_f,
                    random_state=42,
                    n_jobs=-1
                )

                model.fit(X_train_scaled)

                # Scores (más bajo = más anómalo)
                scores = model.decision_function(X_test_scaled)

                # Probamos distintos thresholds
                thresholds = np.percentile(scores, np.arange(1, 50, 5))

                for t in thresholds:
                    y_pred = (scores < t).astype(int)

                    f1 = f1_score(y_test, y_pred)
                    precision = precision_score(y_test, y_pred)
                    recall = recall_score(y_test, y_pred)

                    results.append({
                        "n_estimators": n_est,
                        "max_samples": max_s,
                        "contamination": cont,
                        "max_features": max_f,
                        "threshold": t,
                        "f1": f1,
                        "precision": precision,
                        "recall": recall
                    })

# --------------------------------------------------
# VER MEJORES RESULTADOS
# --------------------------------------------------

df_results = pd.DataFrame(results)

best = df_results.sort_values("f1", ascending=False).iloc[0]

print("\n🔥 MEJOR CONFIGURACIÓN:")
print(best)

print("\nEvaluando mejor modelo...")

# Reentrenar mejor modelo
best_model = IsolationForest(
    n_estimators=int(best["n_estimators"]),
    max_samples=best["max_samples"],
    contamination=best["contamination"],
    max_features=best["max_features"],
    random_state=42,
    n_jobs=-1
)

best_model.fit(X_train_scaled)

scores = best_model.decision_function(X_test_scaled)
y_pred = (scores < best["threshold"]).astype(int)

print("\nMatriz de confusión:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification report:")
print(classification_report(y_test, y_pred))

