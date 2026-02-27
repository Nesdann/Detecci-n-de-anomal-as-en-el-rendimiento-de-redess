from fastapi import FastAPI
from config import state
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from database import obtener_historial_db 


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
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

@app.post("/config/whitelist")
def add_to_whitelist(ip: str):
    if ip not in state.whitelist:
        state.whitelist.append(ip)
    return {"whitelist": state.whitelist}

@app.post("/config/mode")
def set_mode(mode: str):
    # mode puede ser "monitor" o "block"
    if mode in ["monitor", "block"]:
        state.action_mode = mode
    return {"modo_actual": state.action_mode}

@app.get("/ban_list")
def get_ban_list():
    return state.ban_list

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/historial")
def get_historial():
    """Ruta para obtener los ataques guardados en SQLite"""
    data = obtener_historial_db()
    return {"status": "success", "total": len(data), "data": data}