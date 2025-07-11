import sqlite3
import os
from datetime import datetime
from user_module import hash_password

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
        
        # Crear tabla de usuarios actualizada (compatible con user_module.py)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                rol TEXT DEFAULT 'usuario',
                activo INTEGER DEFAULT 1,
                fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
                ultimo_login DATETIME
            )
        ''')
        
        # Crear tabla de sesiones
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sesiones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
                fecha_expiracion DATETIME NOT NULL,
                activa INTEGER DEFAULT 1,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Crear usuario admin por defecto si no existe
        cursor.execute("SELECT id FROM usuarios WHERE email = 'admin@localhost'")
        if not cursor.fetchone():
            admin_password = hash_password('admin123')
            cursor.execute('''
                INSERT INTO usuarios (nombre, email, password_hash, rol)
                VALUES (?, ?, ?, ?)
            ''', ('Administrador', 'admin@localhost', admin_password, 'admin'))
            print("✅ Usuario administrador creado con credenciales: admin@localhost / admin123")
        
        # Confirmar cambios
        conexion.commit()
        print(f"✅ Base de datos creada exitosamente en: {os.path.abspath(db_path)}")
        
        # Mostrar información de las tablas creadas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tablas = cursor.fetchall()
        print("📋 Tablas disponibles:")
        for tabla in tablas:
            print(f"   - {tabla[0]}")
        
        # Mostrar estructura de la tabla usuarios
        cursor.execute("PRAGMA table_info(usuarios)")
        columnas = cursor.fetchall()
        print("\n📊 Estructura de la tabla 'usuarios':")
        for col in columnas:
            print(f"   - {col[1]} ({col[2]})")
        
        conexion.close()
        return True
        
    except Exception as e:
        print(f"❌ Error al crear la base de datos: {e}")
        return False

def migrar_base_datos_existente(db_path='database.db'):
    """
    Migra una base de datos existente para añadir las columnas faltantes.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Verificar si ya existe la tabla usuarios
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
        tabla_existe = cursor.fetchone()
        
        if tabla_existe:
            # Verificar si tiene la columna password_hash
            cursor.execute("PRAGMA table_info(usuarios)")
            columnas = cursor.fetchall()
            columnas_existentes = [col[1] for col in columnas]
            
            if 'password_hash' not in columnas_existentes:
                print("🔄 Migrando tabla usuarios existente...")
                
                # Crear tabla temporal con la estructura nueva
                cursor.execute('''
                    CREATE TABLE usuarios_temp (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        nombre TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        rol TEXT DEFAULT 'usuario',
                        activo INTEGER DEFAULT 1,
                        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
                        ultimo_login DATETIME
                    )
                ''')
                
                # Migrar datos existentes (si los hay)
                cursor.execute("SELECT id, nombre, email FROM usuarios WHERE id != 1")
                usuarios_existentes = cursor.fetchall()
                
                for usuario in usuarios_existentes:
                    # Asignar contraseña temporal
                    password_temp = hash_password('temporal123')
                    cursor.execute('''
                        INSERT INTO usuarios_temp (id, nombre, email, password_hash, rol)
                        VALUES (?, ?, ?, ?, 'usuario')
                    ''', (usuario[0], usuario[1], usuario[2], password_temp))
                
                # Eliminar tabla vieja y renombrar la nueva
                cursor.execute("DROP TABLE usuarios")
                cursor.execute("ALTER TABLE usuarios_temp RENAME TO usuarios")
                
                print("✅ Migración completada. Usuarios existentes tienen contraseña temporal: 'temporal123'")
        
        # Crear usuario admin si no existe
        cursor.execute("SELECT id FROM usuarios WHERE email = 'admin@localhost'")
        if not cursor.fetchone():
            admin_password = hash_password('admin123')
            cursor.execute('''
                INSERT INTO usuarios (nombre, email, password_hash, rol)
                VALUES (?, ?, ?, ?)
            ''', ('Administrador', 'admin@localhost', admin_password, 'admin'))
            print("✅ Usuario administrador creado")
        
        # Crear tabla de sesiones si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sesiones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
                fecha_expiracion DATETIME NOT NULL,
                activa INTEGER DEFAULT 1,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        conexion.commit()
        conexion.close()
        return True
        
    except Exception as e:
        print(f"❌ Error al migrar la base de datos: {e}")
        return False

def verificar_base_datos(db_path='database.db'):
    """
    Verifica si la base de datos y las tablas existen correctamente.
    """
    if not os.path.exists(db_path):
        print(f"⚠️  La base de datos {db_path} no existe.")
        return False
    
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Verificar tablas requeridas
        tablas_requeridas = ['usuarios', 'sesiones', 'logs']
        
        for tabla in tablas_requeridas:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tabla}'")
            if not cursor.fetchone():
                print(f"❌ La tabla '{tabla}' no existe.")
                return False
            else:
                print(f"✅ La tabla '{tabla}' existe correctamente.")
        
        # Verificar estructura de la tabla usuarios
        cursor.execute("PRAGMA table_info(usuarios)")
        columnas = cursor.fetchall()
        columnas_requeridas = ['id', 'nombre', 'email', 'password_hash', 'rol', 'activo', 'fecha_creacion']
        
        columnas_existentes = [col[1] for col in columnas]
        
        print("\n📊 Estructura de la tabla 'usuarios':")
        for col in columnas:
            print(f"   - {col[1]} ({col[2]})")
        
        for col_req in columnas_requeridas:
            if col_req not in columnas_existentes:
                print(f"❌ Falta la columna '{col_req}' en la tabla usuarios.")
                return False
        
        # Verificar usuario admin
        cursor.execute("SELECT nombre FROM usuarios WHERE email = 'admin@localhost'")
        admin = cursor.fetchone()
        if admin:
            print(f"✅ Usuario administrador existe: {admin[0]}")
        else:
            print("⚠️  Usuario administrador no encontrado.")
        
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
            SELECT l.id, u.nombre, l.accion, l.fecha, l.ip_dispositivo 
            FROM logs l
            LEFT JOIN usuarios u ON l.usuario_id = u.id
            ORDER BY l.fecha DESC 
            LIMIT ?
        ''', (limite,))
        
        logs = cursor.fetchall()
        
        if logs:
            print(f"📝 Últimos {len(logs)} logs registrados:")
            print("-" * 80)
            for log in logs:
                usuario = log[1] if log[1] else f"Usuario ID: {log[0]}"
                print(f"ID: {log[0]} | Usuario: {usuario} | IP: {log[4]}")
                print(f"Comando: {log[2]}")
                print(f"Fecha: {log[3]}")
                print("-" * 80)
        else:
            print("ℹ️  No hay logs registrados aún.")
        
        conexion.close()
        
    except Exception as e:
        print(f"❌ Error al mostrar logs: {e}")

if __name__ == "__main__":
    print("🚀 Configurando base de datos para la aplicación de red...")
    
    # Verificar si la base de datos ya existe
    if os.path.exists('database.db'):
        print("📄 Base de datos existente detectada. Migrando...")
        if migrar_base_datos_existente():
            print("✅ Migración completada exitosamente.")
        else:
            print("❌ Error en la migración.")
    else:
        print("🆕 Creando nueva base de datos...")
        if crear_base_datos():
            print("✅ Base de datos creada exitosamente.")
        else:
            print("❌ Error al crear la base de datos.")
    
    # Verificar que todo esté correcto
    print("\n🔍 Verificando base de datos...")
    if verificar_base_datos():
        print("\n🎉 ¡Base de datos lista para usar!")
        print("\n📋 Credenciales de administrador:")
        print("   Email: admin@localhost")
        print("   Contraseña: admin123")
        print("\nPuedes ejecutar tu aplicación Flask ahora:")
        print("python app.py")
    else:
        print("\n❌ Hubo un problema con la verificación.")
