import sqlite3
import time

DB_NAME = "ids_history.db"

def inicializar_db():
    """Crea la tabla de alertas si no existe"""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                src_p TEXT,
                dst_ip TEXT,
                dst_p TEXT,
                tipo TEXT,
                ms REAL
            )
        ''')
        conn.commit()

def guardar_alerta(alerta):
    """Inserta una alerta en la base de datos"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alertas (timestamp, src_ip, src_p, dst_ip, dst_p, tipo, ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (alerta['timestamp'], alerta['src_ip'], alerta['src_p'], 
                  alerta['dst_ip'], alerta['dst_p'], alerta['tipo'], alerta['ms']))
            conn.commit()
    except Exception as e:
        print(f" Error al guardar en DB: {e}")


def obtener_historial_db(limit=100):
    """Recupera las últimas alertas de la base de datos"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.row_factory = sqlite3.Row # Para devolver diccionarios
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alertas ORDER BY id DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"❌ Error al leer DB: {e}")
        return []