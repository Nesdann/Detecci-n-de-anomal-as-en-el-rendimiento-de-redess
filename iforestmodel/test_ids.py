import os
import time

PIPE_PATH = "./ids_pipe"

# Datos de prueba: normal, ataque de flood (muchos bytes/pps) y scan (pocos paquetes)
# Formato: src_ip, dst_ip, src_p, dst_p, proto, ..., duration, pps, bps, bpp
pruebas = [
    # 1. Tráfico Normal (Valores bajos/medios)
    "192.168.1.10,10.0.0.5,443,55600,6,0,0,0,0,10,1500,0,0,0,0,0,0,0,0.5,20,3000,0,0,150,0,0,0,0,0,0,0,0",
    
    # 2. Posible FLOOD (pps e intensity muy altos)
    "172.16.0.5,10.0.0.5,80,443,6,0,0,0,0,5000,900000,0,0,0,0,0,0,0,0.1,50000,8000000,0,0,200,0,0,0,0,0,0,0,0",
    
    # 3. Posible SCAN (pocos paquetes, bpp bajo)
    "1.2.3.4,10.0.0.5,22,60001,6,0,0,0,0,1,40,0,0,0,0,0,0,0,0.01,1,40,0,0,5,0,0,0,0,0,0,0,0"
]

def enviar_pruebas():
    if not os.path.exists(PIPE_PATH):
        print("❌ El pipe no existe. Asegúrate de que ids_engine.py esté corriendo.")
        return

    print("📤 Enviando paquetes de prueba al IDS...")
    with open(PIPE_PATH, "w") as fifo:
        for i, data in enumerate(pruebas):
            fifo.write(data + "\n")
            fifo.flush()
            print(f"✅ Enviada prueba {i+1}")
            time.sleep(2) # Pausa para ver la reacción en la otra consola

if __name__ == "__main__":
    enviar_pruebas()