import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import secrets

def inicializar_tablas_usuarios(db_path='database.db'):
    """
    Inicializa las tablas necesarias para la gestión de usuarios.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Crear tabla de usuarios actualizada
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
        
        conexion.commit()
        conexion.close()
        return True
        
    except Exception as e:
        print(f"Error al inicializar tablas de usuarios: {e}")
        return False

def hash_password(password):
    """
    Genera un hash seguro de la contraseña.
    """
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt + pwd_hash.hex()

def verificar_password(password, hash_almacenado):
    """
    Verifica si una contraseña coincide con su hash.
    """
    try:
        salt = hash_almacenado[:32]
        hash_original = hash_almacenado[32:]
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return pwd_hash.hex() == hash_original
    except:
        return False

def crear_usuario(nombre, email, password, rol='usuario', db_path='database.db'):
    """
    Crea un nuevo usuario.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            return {"status": "error", "mensaje": "El email ya está registrado"}
        
        # Crear usuario
        password_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO usuarios (nombre, email, password_hash, rol)
            VALUES (?, ?, ?, ?)
        ''', (nombre, email, password_hash, rol))
        
        usuario_id = cursor.lastrowid
        conexion.commit()
        conexion.close()
        
        return {"status": "ok", "mensaje": "Usuario creado exitosamente", "usuario_id": usuario_id}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al crear usuario: {str(e)}"}

def autenticar_usuario(email, password, db_path='database.db'):
    """
    Autentica un usuario y retorna sus datos.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            SELECT id, nombre, email, password_hash, rol, activo
            FROM usuarios WHERE email = ?
        ''', (email,))
        
        usuario = cursor.fetchone()
        
        if not usuario:
            return {"status": "error", "mensaje": "Usuario no encontrado"}
        
        if not usuario[5]:  # activo
            return {"status": "error", "mensaje": "Usuario desactivado"}
        
        if not verificar_password(password, usuario[3]):
            return {"status": "error", "mensaje": "Contraseña incorrecta"}
        
        # Actualizar último login
        cursor.execute('''
            UPDATE usuarios SET ultimo_login = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (usuario[0],))
        
        conexion.commit()
        conexion.close()
        
        return {
            "status": "ok",
            "usuario": {
                "id": usuario[0],
                "nombre": usuario[1],
                "email": usuario[2],
                "rol": usuario[4]
            }
        }
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al autenticar: {str(e)}"}

def crear_sesion(usuario_id, db_path='database.db'):
    """
    Crea una nueva sesión para un usuario.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        # Generar token único
        token = secrets.token_urlsafe(32)
        fecha_expiracion = datetime.now() + timedelta(hours=8)
        
        cursor.execute('''
            INSERT INTO sesiones (usuario_id, token, fecha_expiracion)
            VALUES (?, ?, ?)
        ''', (usuario_id, token, fecha_expiracion))
        
        conexion.commit()
        conexion.close()
        
        return {"status": "ok", "token": token}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al crear sesión: {str(e)}"}

def verificar_sesion(token, db_path='database.db'):
    """
    Verifica si una sesión es válida.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            SELECT s.usuario_id, u.nombre, u.email, u.rol
            FROM sesiones s
            JOIN usuarios u ON s.usuario_id = u.id
            WHERE s.token = ? AND s.activa = 1 AND s.fecha_expiracion > CURRENT_TIMESTAMP
        ''', (token,))
        
        sesion = cursor.fetchone()
        conexion.close()
        
        if sesion:
            return {
                "status": "ok",
                "usuario": {
                    "id": sesion[0],
                    "nombre": sesion[1],
                    "email": sesion[2],
                    "rol": sesion[3]
                }
            }
        else:
            return {"status": "error", "mensaje": "Sesión inválida o expirada"}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al verificar sesión: {str(e)}"}

def cerrar_sesion(token, db_path='database.db'):
    """
    Cierra una sesión.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            UPDATE sesiones SET activa = 0
            WHERE token = ?
        ''', (token,))
        
        conexion.commit()
        conexion.close()
        
        return {"status": "ok", "mensaje": "Sesión cerrada"}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al cerrar sesión: {str(e)}"}

def obtener_usuarios(db_path='database.db'):
    """
    Obtiene la lista de todos los usuarios.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        cursor.execute('''
            SELECT id, nombre, email, rol, activo, fecha_creacion, ultimo_login
            FROM usuarios
            ORDER BY fecha_creacion DESC
        ''')
        
        usuarios = cursor.fetchall()
        conexion.close()
        
        return {"status": "ok", "usuarios": usuarios}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al obtener usuarios: {str(e)}"}

def actualizar_usuario(usuario_id, nombre=None, email=None, rol=None, activo=None, db_path='database.db'):
    """
    Actualiza los datos de un usuario.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        updates = []
        params = []
        
        if nombre:
            updates.append("nombre = ?")
            params.append(nombre)
        
        if email:
            updates.append("email = ?")
            params.append(email)
        
        if rol:
            updates.append("rol = ?")
            params.append(rol)
        
        if activo is not None:
            updates.append("activo = ?")
            params.append(activo)
        
        if not updates:
            return {"status": "error", "mensaje": "No hay datos para actualizar"}
        
        params.append(usuario_id)
        query = f"UPDATE usuarios SET {', '.join(updates)} WHERE id = ?"
        
        cursor.execute(query, params)
        conexion.commit()
        conexion.close()
        
        return {"status": "ok", "mensaje": "Usuario actualizado exitosamente"}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al actualizar usuario: {str(e)}"}

def cambiar_password(usuario_id, nueva_password, db_path='database.db'):
    """
    Cambia la contraseña de un usuario.
    """
    try:
        conexion = sqlite3.connect(db_path)
        cursor = conexion.cursor()
        
        nuevo_hash = hash_password(nueva_password)
        
        cursor.execute('''
            UPDATE usuarios SET password_hash = ?
            WHERE id = ?
        ''', (nuevo_hash, usuario_id))
        
        conexion.commit()
        conexion.close()
        
        return {"status": "ok", "mensaje": "Contraseña actualizada exitosamente"}
        
    except Exception as e:
        return {"status": "error", "mensaje": f"Error al cambiar contraseña: {str(e)}"}

if __name__ == "__main__":
    # Inicializar las tablas
    if inicializar_tablas_usuarios():
        print("✅ Tablas de usuarios inicializadas")
        
        # Crear usuario de prueba
        resultado = crear_usuario("Usuario Test", "test@example.com", "password123", "usuario")
        print(f"Crear usuario: {resultado}")
        
        # Autenticar usuario
        auth = autenticar_usuario("admin@localhost", "admin123")
        print(f"Autenticación: {auth}")
        
        if auth["status"] == "ok":
            # Crear sesión
            sesion = crear_sesion(auth["usuario"]["id"])
            print(f"Crear sesión: {sesion}")
            
            if sesion["status"] == "ok":
                # Verificar sesión
                verif = verificar_sesion(sesion["token"])
                print(f"Verificar sesión: {verif}")
