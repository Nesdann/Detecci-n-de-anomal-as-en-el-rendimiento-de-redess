from fastapi import FastAPI
from config import state

app = FastAPI()

@app.get("/status")
def status():
    return {
        "threshold": state.threshold,
        "alertas_totales": len(state.last_alerts),
        "sistema_activo": state.running
    }

@app.post("/config/threshold")
def update_threshold(val: float):
    state.threshold = val
    return {"status": "actualizado", "nuevo_threshold": state.threshold}

@app.get("/alerts")
def get_alerts():
    return state.last_alerts[-10:] # Solo las últimas 10