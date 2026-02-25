from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import time

app = FastAPI()

# Permitir que React  se comunique con este servidor
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base de datos temporal en memoria
alerts_db = []

class Alert(BaseModel):
    timestamp: str
    origen: str
    destino: str
    tipo: str
    score: float

@app.post("/api/alerts")
async def receive_alert(alert: Alert):
    alerts_db.insert(0, alert.dict()) # Poner la más reciente primero
    if len(alerts_db) > 50: alerts_db.pop() # Guardar solo las últimas 50
    return {"status": "ok"}

@app.get("/api/alerts")
async def get_alerts():
    return alerts_db

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)