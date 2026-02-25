class GlobalState:
    def __init__(self):
        self.threshold = 0.05
        self.running = True
        self.last_alerts = []  # Lista de dicts: {"ip": "...", "score": ...}

# Creamos una única instancia para todo el programa

        self.whitelist = ["127.0.0.1", "192.168.1.1"]
        self.action_mode = "monitor" # Opciones: "monitor", "block"
        self.auto_ban_threshold = 3  # Bloquear si hay más de X alertas de la misma IP
        self.ban_list = {} # IP: cantidad_de_alertas
state = GlobalState()