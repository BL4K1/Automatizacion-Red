from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from deploy_module import ejecutar_comando, ejecutar_comando_telnet
from log_module import registrar_log
from user_module import (
    inicializar_tablas_usuarios, autenticar_usuario, crear_sesion,
    verificar_sesion, cerrar_sesion, crear_usuario, obtener_usuarios,
    actualizar_usuario, cambiar_password
)
from functools import wraps

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_super_segura_aqui'  # Cambia esto en producción

# Inicializar las tablas al inicio
inicializar_tablas_usuarios()

def login_required(f):
    """
    Decorador para rutas que requieren autenticación.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        
        # Verificar que la sesión sea válida
        resultado = verificar_sesion(session['user_token'])
        if resultado['status'] != 'ok':
            session.clear()
            flash('Tu sesión ha expirado. Por favor, inicia sesión nuevamente.', 'warning')
            return redirect(url_for('login'))
        
        # Añadir información del usuario al contexto
        session['user_info'] = resultado['usuario']
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """
    Decorador para rutas que requieren permisos de administrador.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_info' not in session or session['user_info']['rol'] != 'admin':
            flash('No tienes permisos para acceder a esta página.', 'danger')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    
    return decorated_function

def procesar_comando(ip, usuario, password, comando, tipo_conexion='ssh'):
    """Función helper para procesar comandos"""
    if not all([ip, usuario, password, comando]):
        return {'error': "❗ Todos los campos son obligatorios."}
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Intentar SSH primero, luego Telnet si falla
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        # Si SSH falla por problemas de algoritmos, sugerir Telnet
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            
            # Intentar automáticamente con Telnet
            resultado_telnet = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado_telnet['status'] == 'ok':
                resultado = resultado_telnet
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
            else:
                resultado['salida'] += f"\n\n💡 Sugerencia: Este router podría tener SSH con algoritmos antiguos. Intenta usar Telnet."
    
    elif tipo_conexion == 'telnet':
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion=comando, ip_dispositivo=ip)
        return {'salida': resultado['salida']}
    else:
        return {'error': resultado['salida']}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        resultado = autenticar_usuario(email, password)
        
        if resultado['status'] == 'ok':
            # Crear sesión
            sesion = crear_sesion(resultado['usuario']['id'])
            if sesion['status'] == 'ok':
                session['user_token'] = sesion['token']
                session['user_info'] = resultado['usuario']
                flash(f'¡Bienvenido, {resultado["usuario"]["nombre"]}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Error al crear la sesión.', 'danger')
        else:
            flash(resultado['mensaje'], 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if 'user_token' in session:
        cerrar_sesion(session['user_token'])
    
    session.clear()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmar_password = request.form.get('confirmar_password')
        
        if password != confirmar_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_template('registro.html')
        
        resultado = crear_usuario(nombre, email, password)
        
        if resultado['status'] == 'ok':
            flash('Usuario registrado exitosamente. Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        else:
            flash(resultado['mensaje'], 'danger')
    
    return render_template('registro.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        ip = request.form.get('ip')
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        comando = request.form.get('comando')
        tipo_conexion = request.form.get('tipo_conexion', 'ssh')
        
        resultado = procesar_comando(ip, usuario, password, comando, tipo_conexion)
        return render_template('index.html', **resultado)
    
    return render_template('index.html')

@app.route('/ejecutar', methods=['POST'])
@login_required
def ejecutar():
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    comando = request.form.get('comando')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    # Detectar desde qué página viene la petición
    referer = request.headers.get('Referer', '')
    template_to_render = 'gestion.html' if '/gestion' in referer else 'index.html'

    resultado = procesar_comando(ip, usuario, password, comando, tipo_conexion)
    return render_template(template_to_render, **resultado)

@app.route('/gestion', methods=['GET', 'POST'])
@login_required
def gestion():
    if request.method == 'POST':
        ip = request.form.get('ip')
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        comando = request.form.get('comando')
        tipo_conexion = request.form.get('tipo_conexion', 'ssh')
        
        resultado = procesar_comando(ip, usuario, password, comando, tipo_conexion)
        return render_template('gestion.html', **resultado)
    
    return render_template('gestion.html')

@app.route('/seguridad', methods=['GET', 'POST'])
@login_required
def seguridad():
    if request.method == 'POST':
        ip = request.form.get('ip')
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        comando = request.form.get('comando')
        tipo_conexion = request.form.get('tipo_conexion', 'ssh')
        
        resultado = procesar_comando(ip, usuario, password, comando, tipo_conexion)
        return render_template('seguridad.html', **resultado)
    
    return render_template('seguridad.html')

@app.route('/mantenimiento', methods=['GET', 'POST'])
@login_required
def mantenimiento():
    if request.method == 'POST':
        ip = request.form.get('ip')
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        comando = request.form.get('comando')
        tipo_conexion = request.form.get('tipo_conexion', 'ssh')
        
        resultado = procesar_comando(ip, usuario, password, comando, tipo_conexion)
        return render_template('mantenimiento.html', **resultado)
    
    return render_template('mantenimiento.html')

# --- RUTAS DE ADMINISTRACIÓN DE USUARIOS ---

@app.route('/admin/usuarios')
@login_required
@admin_required
def admin_usuarios():
    """Página de administración de usuarios"""
    resultado = obtener_usuarios()
    usuarios = resultado.get('usuarios', []) if resultado['status'] == 'ok' else []
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/crear', methods=['POST'])
@login_required
@admin_required
def admin_crear_usuario():
    """Crear nuevo usuario desde el panel de admin"""
    nombre = request.form.get('nombre')
    email = request.form.get('email')
    password = request.form.get('password')
    rol = request.form.get('rol', 'usuario')
    
    resultado = crear_usuario(nombre, email, password, rol)
    
    if resultado['status'] == 'ok':
        flash('Usuario creado exitosamente.', 'success')
    else:
        flash(resultado['mensaje'], 'danger')
    
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuarios/actualizar/<int:usuario_id>', methods=['POST'])
@login_required
@admin_required
def admin_actualizar_usuario(usuario_id):
    """Actualizar usuario"""
    nombre = request.form.get('nombre')
    email = request.form.get('email')
    rol = request.form.get('rol')
    activo = request.form.get('activo') == '1'
    
    resultado = actualizar_usuario(usuario_id, nombre, email, rol, activo)
    
    if resultado['status'] == 'ok':
        flash('Usuario actualizado exitosamente.', 'success')
    else:
        flash(resultado['mensaje'], 'danger')
    
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuarios/cambiar-password/<int:usuario_id>', methods=['POST'])
@login_required
@admin_required
def admin_cambiar_password(usuario_id):
    """Cambiar contraseña de usuario"""
    nueva_password = request.form.get('nueva_password')
    
    resultado = cambiar_password(usuario_id, nueva_password)
    
    if resultado['status'] == 'ok':
        flash('Contraseña actualizada exitosamente.', 'success')
    else:
        flash(resultado['mensaje'], 'danger')
    
    return redirect(url_for('admin_usuarios'))

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    """Página de perfil del usuario"""
    if request.method == 'POST':
        accion = request.form.get('accion')
        
        if accion == 'cambiar_password':
            password_actual = request.form.get('password_actual')
            nueva_password = request.form.get('nueva_password')
            confirmar_password = request.form.get('confirmar_password')
            
            if nueva_password != confirmar_password:
                flash('Las contraseñas no coinciden.', 'danger')
                return render_template('perfil.html')
            
            # Verificar contraseña actual
            auth = autenticar_usuario(session['user_info']['email'], password_actual)
            if auth['status'] != 'ok':
                flash('Contraseña actual incorrecta.', 'danger')
                return render_template('perfil.html')
            
            # Cambiar contraseña
            resultado = cambiar_password(session['user_info']['id'], nueva_password)
            if resultado['status'] == 'ok':
                flash('Contraseña actualizada exitosamente.', 'success')
            else:
                flash(resultado['mensaje'], 'danger')
        
        elif accion == 'actualizar_perfil':
            nombre = request.form.get('nombre')
            email = request.form.get('email')
            
            resultado = actualizar_usuario(session['user_info']['id'], nombre, email)
            if resultado['status'] == 'ok':
                # Actualizar información en la sesión
                session['user_info']['nombre'] = nombre
                session['user_info']['email'] = email
                flash('Perfil actualizado exitosamente.', 'success')
            else:
                flash(resultado['mensaje'], 'danger')
    
    return render_template('perfil.html')

# Context processor para hacer la información del usuario disponible en todas las plantillas
@app.context_processor
def inject_user_info():
    return {
        'user_info': session.get('user_info', None),
        'is_admin': session.get('user_info', {}).get('rol') == 'admin'
    }


# Agregar esta nueva ruta después de la ruta /perfil en app.py

@app.route('/descargar-backup', methods=['POST'])
@login_required
def descargar_backup():
    """Generar y descargar backup de configuración"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    tipo_backup = request.form.get('tipo_backup', 'running')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Determinar el comando según el tipo de backup
    comando = 'show running-config' if tipo_backup == 'running' else 'show startup-config'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando para obtener la configuración
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        # Si SSH falla, intentar con Telnet
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"! Conectado vía Telnet\n!\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        # Registrar la acción en el log
        registrar_log(usuario_id=usuario_id, accion=f"Backup {tipo_backup}-config", ip_dispositivo=ip)
        
        # Preparar el contenido del archivo
        contenido = resultado['salida']
        
        # Agregar encabezado con información del backup
        from datetime import datetime
        fecha_actual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        encabezado = f"""!
! Backup de configuración - {tipo_backup.upper()}-CONFIG
! Dispositivo: {ip}
! Fecha: {fecha_actual}
! Usuario: {session.get('user_info', {}).get('nombre', 'N/A')}
! Generado por: Sistema de Automatización de Red
!
"""
        
        contenido_completo = encabezado + contenido
        
        # Crear nombre del archivo
        nombre_archivo = f"backup_{ip}_{tipo_backup}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Crear respuesta para descarga
        from flask import make_response
        response = make_response(contenido_completo)
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = f'attachment; filename={nombre_archivo}'
        
        return response
    else:
        return jsonify({'error': resultado['salida']}), 500


# Agregar esta nueva ruta en app.py después de la ruta /descargar-backup

@app.route('/ejecutar-comando-json', methods=['POST'])
@login_required
def ejecutar_comando_json():
    """
    Endpoint específico para ejecutar comandos y retornar JSON
    """
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    comando = request.form.get('comando')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password, comando]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        # Si SSH falla por problemas de algoritmos, sugerir Telnet
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            
            # Intentar automáticamente con Telnet
            resultado_telnet = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado_telnet['status'] == 'ok':
                resultado = resultado_telnet
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
            else:
                resultado['salida'] += f"\n\n💡 Sugerencia: Este router podría tener SSH con algoritmos antiguos. Intenta usar Telnet."
    
    elif tipo_conexion == 'telnet':
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion=comando, ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': f'Comando "{comando}" ejecutado exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': f'Error al ejecutar comando "{comando}"'
        }), 500


# --- FUNCIONES DE SEGURIDAD DEL ROUTER ---

@app.route('/security/listar-usuarios', methods=['POST'])
@login_required
def security_listar_usuarios():
    """Listar usuarios del router"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para listar usuarios
    comando = 'show running-config | include username'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Listar usuarios del router", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': 'Usuarios listados exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al listar usuarios'
        }), 500

@app.route('/security/crear-usuario', methods=['POST'])
@login_required
def security_crear_usuario():
    """Crear usuario en el router"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    # Datos del nuevo usuario
    nuevo_usuario = request.form.get('nuevo_usuario')
    nueva_password = request.form.get('nueva_password')
    privilegio = request.form.get('privilegio', '15')
    metodo_auth = request.form.get('metodo_auth', 'local')
    
    if not all([ip, usuario, password, nuevo_usuario, nueva_password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Construir comandos de configuración - CORREGIDO
    comandos = [
        'configure terminal',
        f'username {nuevo_usuario} privilege {privilegio} secret {nueva_password}',
        'end',
        'write memory'
    ]
    
    # Ejecutar comandos uno por uno en lugar de concatenarlos
    resultado_final = {'status': 'ok', 'salida': ''}
    
    for comando in comandos:
        if tipo_conexion == 'ssh':
            resultado = ejecutar_comando(ip, usuario, password, comando)
            
            if (resultado['status'] == 'error' and 
                ('tiempo de espera' in resultado['salida'].lower() or 
                 'algoritmos' in resultado['salida'].lower())):
                resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
        else:
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
        
        if resultado['status'] == 'error':
            return jsonify({
                'status': 'error',
                'error': resultado['salida'],
                'mensaje': f'Error al ejecutar comando: {comando}'
            }), 500
        
        resultado_final['salida'] += f"{comando}\n{resultado['salida']}\n"
    
    registrar_log(usuario_id=usuario_id, accion=f"Crear usuario {nuevo_usuario} (privilegio {privilegio})", ip_dispositivo=ip)
    return jsonify({
        'status': 'success',
        'salida': resultado_final['salida'],
        'mensaje': f'Usuario {nuevo_usuario} creado exitosamente'
    })

@app.route('/security/eliminar-usuario', methods=['POST'])
@login_required
def security_eliminar_usuario():
    """Eliminar usuario del router"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    # Usuario a eliminar
    usuario_eliminar = request.form.get('usuario_eliminar')
    
    if not all([ip, usuario, password, usuario_eliminar]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Comandos para eliminar usuario - CORREGIDO
    comandos = [
        'configure terminal',
        f'no username {usuario_eliminar}',
        'end',
        'write memory'
    ]
    
    # Ejecutar comandos uno por uno
    resultado_final = {'status': 'ok', 'salida': ''}
    
    for comando in comandos:
        if tipo_conexion == 'ssh':
            resultado = ejecutar_comando(ip, usuario, password, comando)
            
            if (resultado['status'] == 'error' and 
                ('tiempo de espera' in resultado['salida'].lower() or 
                 'algoritmos' in resultado['salida'].lower())):
                resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
        else:
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
        
        if resultado['status'] == 'error':
            return jsonify({
                'status': 'error',
                'error': resultado['salida'],
                'mensaje': f'Error al ejecutar comando: {comando}'
            }), 500
        
        resultado_final['salida'] += f"{comando}\n{resultado['salida']}\n"
    
    registrar_log(usuario_id=usuario_id, accion=f"Eliminar usuario {usuario_eliminar}", ip_dispositivo=ip)
    return jsonify({
        'status': 'success',
        'salida': resultado_final['salida'],
        'mensaje': f'Usuario {usuario_eliminar} eliminado exitosamente'
    })

@app.route('/security/mostrar-privilegios', methods=['POST'])
@login_required
def security_mostrar_privilegios():
    """Mostrar privilegios del usuario actual"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para mostrar privilegios
    comando = 'show privilege'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Mostrar privilegios", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': 'Privilegios obtenidos exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al obtener privilegios'
        }), 500

@app.route('/security/escanear-dispositivos', methods=['POST'])
@login_required
def security_escanear_dispositivos():
    """Escanear dispositivos conectados"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para obtener tabla ARP
    comando = 'show ip arp'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Escanear dispositivos (ARP)", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': 'Escaneo de dispositivos completado'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al escanear dispositivos'
        }), 500

@app.route('/security/tabla-arp', methods=['POST'])
@login_required
def security_tabla_arp():
    """Mostrar tabla ARP completa"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para tabla ARP detallada
    comando = 'show arp'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Mostrar tabla ARP", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': 'Tabla ARP obtenida exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al obtener tabla ARP'
        }), 500

@app.route('/security/vecinos-cdp', methods=['POST'])
@login_required
def security_vecinos_cdp():
    """Mostrar vecinos CDP/LLDP"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Primero intentar CDP
    comando_cdp = 'show cdp neighbors detail'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando CDP
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando_cdp)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando_cdp)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando_cdp)
    
    # Si CDP no funciona, intentar LLDP
    if resultado['status'] == 'error' or 'not enabled' in resultado['salida'].lower():
        comando_lldp = 'show lldp neighbors detail'
        
        if tipo_conexion == 'ssh':
            resultado_lldp = ejecutar_comando(ip, usuario, password, comando_lldp)
            
            if (resultado_lldp['status'] == 'error' and 
                ('tiempo de espera' in resultado_lldp['salida'].lower() or 
                 'algoritmos' in resultado_lldp['salida'].lower())):
                resultado_lldp = ejecutar_comando_telnet(ip, usuario, password, comando_lldp)
                if resultado_lldp['status'] == 'ok':
                    resultado_lldp['salida'] = f"[Conectado vía Telnet]\n\n{resultado_lldp['salida']}"
        else:
            resultado_lldp = ejecutar_comando_telnet(ip, usuario, password, comando_lldp)
        
        if resultado_lldp['status'] == 'ok':
            resultado = resultado_lldp
            protocolo = "LLDP"
        else:
            protocolo = "CDP/LLDP"
    else:
        protocolo = "CDP"
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion=f"Mostrar vecinos {protocolo}", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': f'Vecinos {protocolo} obtenidos exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': f'Error al obtener vecinos {protocolo}'
        }), 500

@app.route('/security/logs-auth', methods=['POST'])
@login_required
def security_logs_auth():
    """Mostrar logs de autenticación"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para logs de autenticación
    comando = 'show logging | include LOGIN'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Ver logs de autenticación", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'] if resultado['salida'].strip() else 'No hay logs de autenticación recientes',
            'mensaje': 'Logs de autenticación obtenidos'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al obtener logs de autenticación'
        }), 500

@app.route('/security/logs-config', methods=['POST'])
@login_required
def security_logs_config():
    """Mostrar logs de configuración"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para logs de configuración
    comando = 'show logging | include CONFIG'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Ver logs de configuración", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'] if resultado['salida'].strip() else 'No hay logs de configuración recientes',
            'mensaje': 'Logs de configuración obtenidos'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al obtener logs de configuración'
        }), 500

@app.route('/security/logs-conexion', methods=['POST'])
@login_required
def security_logs_conexion():
    """Mostrar logs de conexión"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para logs de conexión
    comando = 'show logging | include LINK'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Ver logs de conexión", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'] if resultado['salida'].strip() else 'No hay logs de conexión recientes',
            'mensaje': 'Logs de conexión obtenidos'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al obtener logs de conexión'
        }), 500

@app.route('/security/verificar-conexion', methods=['POST'])
@login_required
def security_verificar_conexion():
    """Verificar conexión y estado del router"""
    ip = request.form.get('ip')
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    tipo_conexion = request.form.get('tipo_conexion', 'ssh')
    
    if not all([ip, usuario, password]):
        return jsonify({'error': "❗ Todos los campos son obligatorios."}), 400
    
    # Comando para verificar estado
    comando = 'show version | include uptime'
    
    # Obtener ID del usuario actual
    usuario_id = session.get('user_info', {}).get('id', 1)
    
    # Ejecutar comando
    if tipo_conexion == 'ssh':
        resultado = ejecutar_comando(ip, usuario, password, comando)
        
        if (resultado['status'] == 'error' and 
            ('tiempo de espera' in resultado['salida'].lower() or 
             'algoritmos' in resultado['salida'].lower())):
            resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
            if resultado['status'] == 'ok':
                resultado['salida'] = f"[Conectado vía Telnet]\n\n{resultado['salida']}"
    else:
        resultado = ejecutar_comando_telnet(ip, usuario, password, comando)
    
    if resultado['status'] == 'ok':
        registrar_log(usuario_id=usuario_id, accion="Verificar conexión", ip_dispositivo=ip)
        return jsonify({
            'status': 'success',
            'salida': resultado['salida'],
            'mensaje': 'Conexión verificada exitosamente'
        })
    else:
        return jsonify({
            'status': 'error',
            'error': resultado['salida'],
            'mensaje': 'Error al verificar conexión'
        }), 500


if __name__ == '__main__':
    app.run(debug=True, port=5001)
