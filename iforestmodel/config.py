class GlobalState:
    def __init__(self):
        self.threshold = 0.05
        self.running = True
        self.last_alerts = []  # Lista de dicts: {"ip": "...", "score": ...}

# Creamos una única instancia para todo el programa
state = GlobalState()