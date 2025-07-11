import sqlite3
import os
from datetime import datetime

def crear_base_datos(db_path='database.db'):
    """
    Crea la base de datos y las tablas necesarias para la aplicación.
    """
    try:
        # Crear conexión a la base de datos
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Crear tabla de logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                accion TEXT NOT NULL,
                fecha DATETIME NOT NULL,
                ip_dispositivo TEXT NOT NULL
            )
        ''')
        
        # Crear tabla de usuarios (opcional, para futuras funcionalidades)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE,
                fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insertar un usuario por defecto
        cursor.execute('''
            INSERT OR IGNORE INTO usuarios (id, nombre, email)
            VALUES (1, 'Admin', 'admin@localhost')
        ''')
        
        # Confirmar cambios
        conexion.commit()
        print(f"✅ Base de datos creada exitosamente en: {os.path.abspath(db_path)}")
        
        # Mostrar información de las tablas creadas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tablas = cursor.fetchall()
        print("📋 Tablas disponibles:")
        for tabla in tablas:
            print(f"   - {tabla[0]}")
        
        conexion.close()
        return True
        
    except Exception as e:
        print(f"❌ Error al crear la base de datos: {e}")
        return False

def verificar_base_datos(db_path='database.db'):
    """
    Verifica si la base de datos y las tablas existen.
    """
    if not os.path.exists(db_path):
        print(f"⚠️  La base de datos {db_path} no existe.")
        return False
    
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Verificar si la tabla logs existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        tabla_logs = cursor.fetchone()
        
        if tabla_logs:
            print("✅ La tabla 'logs' existe correctamente.")
            
            # Mostrar estructura de la tabla
            cursor.execute("PRAGMA table_info(logs)")
            columnas = cursor.fetchall()
            print("📊 Estructura de la tabla 'logs':")
            for col in columnas:
                print(f"   - {col[1]} ({col[2]})")
        else:
            print("❌ La tabla 'logs' no existe.")
            return False
        
        conexion.close()
        return True
        
    except Exception as e:
        print(f"❌ Error al verificar la base de datos: {e}")
        return False

def mostrar_logs(db_path='database.db', limite=10):
    """
    Muestra los últimos logs registrados.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            SELECT id, usuario_id, accion, fecha, ip_dispositivo 
            FROM logs 
            ORDER BY fecha DESC 
            LIMIT ?
        ''', (limite,))
        
        logs = cursor.fetchall()
        
        if logs:
            print(f"📝 Últimos {len(logs)} logs registrados:")
            print("-" * 80)
            for log in logs:
                print(f"ID: {log[0]} | Usuario: {log[1]} | IP: {log[4]}")
                print(f"Comando: {log[2]}")
                print(f"Fecha: {log[3]}")
                print("-" * 80)
        else:
            print("ℹ️  No hay logs registrados aún.")
        
        conexion.close()
        
    except Exception as e:
        print(f"❌ Error al mostrar logs: {e}")

if __name__ == "__main__":
    print("🚀 Inicializando base de datos para la aplicación de red...")
    
    # Crear la base de datos
    if crear_base_datos():
        # Verificar que todo esté correcto
        if verificar_base_datos():
            print("\n🎉 ¡Base de datos lista para usar!")
            print("\nPuedes ejecutar tu aplicación Flask ahora:")
            print("python app.py")
        else:
            print("\n❌ Hubo un problema con la verificación.")
    else:
        print("\n❌ No se pudo crear la base de datos.")
