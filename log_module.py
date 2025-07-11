import sqlite3
import os
from datetime import datetime

def inicializar_base_datos(db_path='database.db'):
    """
    Inicializa la base de datos si no existe.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Crear tabla de logs si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                accion TEXT NOT NULL,
                fecha DATETIME NOT NULL,
                ip_dispositivo TEXT NOT NULL
            )
        ''')
        
        # Crear tabla de usuarios si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE,
                fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insertar usuario por defecto
        cursor.execute('''
            INSERT OR IGNORE INTO usuarios (id, nombre, email)
            VALUES (1, 'Admin', 'admin@localhost')
        ''')
        
        conexion.commit()
        conexion.close()
        return True
        
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")
        return False

def registrar_log(usuario_id, accion, ip_dispositivo, db_path='database.db'):
    """
    Registra un log en la base de datos.
    Incluye manejo de errores y inicialización automática.
    """
    try:
        # Verificar si la base de datos existe, si no, crearla
        if not os.path.exists(db_path):
            print(f"Base de datos no encontrada. Creando {db_path}...")
            if not inicializar_base_datos(db_path):
                print("❌ Error al crear la base de datos")
                return False
        
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Verificar si la tabla logs existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if not cursor.fetchone():
            print("Tabla 'logs' no encontrada. Inicializando base de datos...")
            conexion.close()
            if not inicializar_base_datos(db_path):
                print("❌ Error al inicializar la base de datos")
                return False
            conexion = sqlite3.connect(db_path)
            cursor = conexion.cursor()
        
        # Registrar el log
        cursor.execute('''
            INSERT INTO logs (usuario_id, accion, fecha, ip_dispositivo)
            VALUES (?, ?, ?, ?)
        ''', (usuario_id, accion, datetime.now(), ip_dispositivo))
        
        conexion.commit()
        conexion.close()
        
        print(f"✅ Log registrado: {accion} en {ip_dispositivo}")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Error de SQLite al registrar log: {e}")
        return False
    except Exception as e:
        print(f"❌ Error inesperado al registrar log: {e}")
        return False

def obtener_logs(limite=50, db_path='database.db'):
    """
    Obtiene los logs más recientes de la base de datos.
    """
    try:
        if not os.path.exists(db_path):
            print("⚠️  Base de datos no encontrada")
            return []
        
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            SELECT l.id, u.nombre, l.accion, l.fecha, l.ip_dispositivo
            FROM logs l
            LEFT JOIN usuarios u ON l.usuario_id = u.id
            ORDER BY l.fecha DESC
            LIMIT ?
        ''', (limite,))
        
        logs = cursor.fetchall()
        conexion.close()
        
        return logs
        
    except sqlite3.Error as e:
        print(f"❌ Error de SQLite al obtener logs: {e}")
        return []
    except Exception as e:
        print(f"❌ Error inesperado al obtener logs: {e}")
        return []

def limpiar_logs_antiguos(dias=30, db_path='database.db'):
    """
    Elimina logs más antiguos que el número de días especificado.
    """
    try:
        if not os.path.exists(db_path):
            print("⚠️  Base de datos no encontrada")
            return False
        
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            DELETE FROM logs 
            WHERE fecha < datetime('now', '-' || ? || ' days')
        ''', (dias,))
        
        logs_eliminados = cursor.rowcount
        conexion.commit()
        conexion.close()
        
        print(f"🗑️  {logs_eliminados} logs antiguos eliminados")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Error de SQLite al limpiar logs: {e}")
        return False
    except Exception as e:
        print(f"❌ Error inesperado al limpiar logs: {e}")
        return False

if __name__ == "__main__":
    # Prueba del módulo
    print("🧪 Probando el módulo de logs...")
    
    # Inicializar base de datos
    if inicializar_base_datos():
        print("✅ Base de datos inicializada")
        
        # Registrar un log de prueba
        if registrar_log(1, "show version", "192.168.1.1"):
            print("✅ Log de prueba registrado")
            
            # Obtener logs
            logs = obtener_logs(5)
            print(f"📊 {len(logs)} logs encontrados")
            
            for log in logs:
                print(f"  - {log[1]} ejecutó '{log[2]}' en {log[4]} el {log[3]}")
        else:
            print("❌ Error al registrar log de prueba")
    else:
        print("❌ Error al inicializar base de datos")
