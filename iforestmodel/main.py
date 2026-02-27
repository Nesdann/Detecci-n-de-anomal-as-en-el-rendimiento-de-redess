import threading
import uvicorn
from ids_engine import run_engine
from api_control import app
from database import inicializar_db

if __name__ == "__main__":
    inicializar_db()
    engine_thread = threading.Thread(target=run_engine)
    engine_thread.daemon = True  # Para que muera si cerrás el main
    engine_thread.start()

    # 2. Lanzamos la API en el hilo principal
    # Host 0.0.0.0 permite que entres desde tu celular u otra PC
    uvicorn.run(app, host="0.0.0.0", port=8000)