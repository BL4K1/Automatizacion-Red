from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
from typing import Dict, List, Tuple, Optional
import paramiko
import re
import time

def _create_connection(ip: str, username: str, password: str, protocol: str = 'telnet') -> Dict:
    """
    Crea y retorna una conexión a un dispositivo de red.
    Por defecto usa Telnet para compatibilidad con routers antiguos.
    """
    try:
        device_type = 'cisco_ios_telnet' if protocol.lower() == 'telnet' else 'cisco_ios'
        
        device_config = {
            'device_type': device_type,
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 30,
            'session_timeout': 90,
            'banner_timeout': 20,
            'conn_timeout': 15,
        }

        # Configuraciones específicas para SSH (solo si se usa SSH)
        if protocol.lower() == 'ssh':
            device_config.update({
                'ssh_config_file': None,
                'allow_agent': False,
                'look_for_keys': False,
                'use_keys': False,
                'key_policy': paramiko.AutoAddPolicy(),
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']
                }
            })

        connection = ConnectHandler(**device_config)
        return {
            "status": "success", 
            "connection": connection, 
            "message": f"Conexión {protocol.upper()} establecida exitosamente"
        }

    except NetMikoAuthenticationException:
        return {
            "status": "error", 
            "connection": None, 
            "message": f"Error de autenticación {protocol.upper()}: Credenciales incorrectas"
        }
    except NetMikoTimeoutException:
        return {
            "status": "error", 
            "connection": None, 
            "message": f"Tiempo de espera agotado en {protocol.upper()}: El dispositivo no responde"
        }
    except Exception as e:
        return {
            "status": "error", 
            "connection": None, 
            "message": f"Error de conexión {protocol.upper()}: {str(e)}"
        }

def execute_command(ip: str, username: str, password: str, command: str, protocol: str = 'telnet', config_mode: bool = False) -> Tuple[bool, str]:
    """
    Ejecuta un comando en un dispositivo de red.
    Por defecto usa Telnet.
    
    Args:
        ip: Dirección IP del dispositivo
        username: Usuario para autenticación
        password: Contraseña para autenticación
        command: Comando a ejecutar
        protocol: Protocolo de conexión ('telnet' o 'ssh')
        config_mode: Si se requiere modo configuración
    
    Returns:
        Tuple[bool, str]: (éxito, resultado/error)
    """
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        
        if config_mode:
            connection.enable()
            connection.config_mode()
            output = connection.send_command(command)
            connection.exit_config_mode()
        else:
            output = connection.send_command(command)
        
        connection.disconnect()
        return True, output
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error ejecutando comando: {str(e)}"

def test_connection(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Prueba la conectividad con el dispositivo de red.
    
    Args:
        ip: Dirección IP del dispositivo
        username: Usuario para autenticación
        password: Contraseña para autenticación
        protocol: Protocolo de conexión
    
    Returns:
        Tuple[bool, str]: (éxito, mensaje)
    """
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] == "success":
        try:
            connection = conn_result["connection"]
            output = connection.send_command('show version | include uptime')
            connection.disconnect()
            return True, f"Conexión {protocol.upper()} exitosa - {output.strip()}"
        except Exception as e:
            return False, f"Error en prueba de conexión: {str(e)}"
    else:
        return False, conn_result["message"]

# ==================== FUNCIONES DE CONFIGURACIÓN ====================

def get_config(ip: str, username: str, password: str, protocol: str = 'telnet', config_type: str = 'running') -> Tuple[bool, str]:
    """
    Obtiene la configuración del router.
    
    Args:
        config_type: 'running', 'startup', 'version'
    """
    commands = {
        'running': 'show running-config',
        'startup': 'show startup-config',
        'version': 'show version'
    }
    
    command = commands.get(config_type, 'show running-config')
    return execute_command(ip, username, password, command, protocol)

def get_interfaces(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, List[Dict], str]:
    """
    Obtiene información de todas las interfaces.
    
    Returns:
        Tuple[bool, List[Dict], str]: (éxito, lista_interfaces, mensaje)
    """
    success, output = execute_command(ip, username, password, 'show ip interface brief', protocol)
    
    if not success:
        return False, [], output
    
    interfaces = []
    lines = output.split('\n')
    
    for line in lines[1:]:  # Saltar header
        if line.strip() and not line.startswith('Interface'):
            parts = line.split()
            if len(parts) >= 6:
                interface = {
                    'name': parts[0],
                    'ip_address': parts[1] if parts[1] != 'unassigned' else '',
                    'status': parts[4],
                    'protocol': parts[5]
                }
                interfaces.append(interface)
    
    return True, interfaces, f"{len(interfaces)} interfaces encontradas"

def get_routing_table(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, List[Dict], str]:
    """
    Obtiene la tabla de enrutamiento.
    
    Returns:
        Tuple[bool, List[Dict], str]: (éxito, lista_rutas, mensaje)
    """
    success, output = execute_command(ip, username, password, 'show ip route', protocol)
    
    if not success:
        return False, [], output
    
    routes = []
    lines = output.split('\n')
    
    for line in lines:
        if re.match(r'^[CSDROBIE*]\s', line.strip()):
            parts = line.split()
            if len(parts) >= 3:
                route = {
                    'type': parts[0],
                    'network': parts[1],
                    'next_hop': parts[2] if len(parts) > 2 else '',
                    'interface': parts[-1] if '[' not in parts[-1] else ''
                }
                routes.append(route)
    
    return True, routes, f"{len(routes)} rutas encontradas"

# ==================== FUNCIONES DE USUARIOS ====================

def get_users(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, List[Dict], str]:
    """
    Obtiene lista de usuarios configurados.
    """
    success, output = execute_command(ip, username, password, 'show running-config | include username', protocol)
    
    if not success:
        return False, [], output
    
    users = []
    lines = output.split('\n')
    
    for line in lines:
        if 'username' in line:
            parts = line.split()
            if len(parts) >= 2:
                user = {
                    'username': parts[1],
                    'privilege_level': '1',  # default
                    'status': 'active'
                }
                
                # Buscar privilege level
                for part in parts:
                    if part.isdigit():
                        user['privilege_level'] = part
                        break
                
                users.append(user)
    
    return True, users, f"{len(users)} usuarios encontrados"

def add_user(ip: str, username: str, password: str, new_username: str, new_password: str, privilege_level: str = '15', protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Agrega un nuevo usuario al router.
    
    Args:
        ip: IP del router
        username: Usuario admin actual
        password: Contraseña admin actual
        new_username: Nuevo usuario a crear
        new_password: Contraseña del nuevo usuario
        privilege_level: Nivel de privilegio (1-15)
        protocol: Protocolo de conexión
    """
    commands = [
        f'username {new_username} privilege {privilege_level} password {new_password}'
    ]
    
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        
        for cmd in commands:
            connection.send_command(cmd)
        
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Usuario {new_username} agregado exitosamente con privilegio {privilege_level}"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error agregando usuario: {str(e)}"

def delete_user(ip: str, username: str, password: str, target_username: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Elimina un usuario del router.
    """
    command = f'no username {target_username}'
    
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        connection.send_command(command)
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Usuario {target_username} eliminado exitosamente"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error eliminando usuario: {str(e)}"

def update_user_password(ip: str, username: str, password: str, target_username: str, new_password: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Actualiza la contraseña de un usuario.
    """
    # Obtener privilege level actual
    success, users, _ = get_users(ip, username, password, protocol)
    privilege_level = '15'  # default
    
    if success:
        for user in users:
            if user['username'] == target_username:
                privilege_level = user['privilege_level']
                break
    
    command = f'username {target_username} privilege {privilege_level} password {new_password}'
    
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        connection.send_command(command)
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Contraseña de {target_username} actualizada exitosamente"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error actualizando contraseña: {str(e)}"

# ==================== FUNCIONES DE INTERFACES ====================

def configure_interface_description(ip: str, username: str, password: str, interface_name: str, description: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Configura la descripción de una interfaz.
    """
    commands = [
        f'interface {interface_name}',
        f'description {description}'
    ]
    
    return _execute_interface_commands(ip, username, password, protocol, commands, f"configurando descripción en {interface_name}")

def enable_interface(ip: str, username: str, password: str, interface_name: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Habilita una interfaz.
    """
    commands = [
        f'interface {interface_name}',
        'no shutdown'
    ]
    
    return _execute_interface_commands(ip, username, password, protocol, commands, f"habilitando {interface_name}")

def disable_interface(ip: str, username: str, password: str, interface_name: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Deshabilita una interfaz.
    """
    commands = [
        f'interface {interface_name}',
        'shutdown'
    ]
    
    return _execute_interface_commands(ip, username, password, protocol, commands, f"deshabilitando {interface_name}")

def set_interface_ip(ip: str, username: str, password: str, interface_name: str, ip_address: str, subnet_mask: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Configura IP en una interfaz.
    """
    commands = [
        f'interface {interface_name}',
        f'ip address {ip_address} {subnet_mask}',
        'no shutdown'
    ]
    
    return _execute_interface_commands(ip, username, password, protocol, commands, f"configurando IP {ip_address}/{subnet_mask} en {interface_name}")

def _execute_interface_commands(ip: str, username: str, password: str, protocol: str, commands: List[str], action: str) -> Tuple[bool, str]:
    """
    Función auxiliar para ejecutar comandos de interfaz.
    """
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        
        for cmd in commands:
            connection.send_command(cmd)
        
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Éxito {action}"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error {action}: {str(e)}"

# ==================== FUNCIONES DE RUTAS ====================

def add_route(ip: str, username: str, password: str, network: str, subnet_mask: str, next_hop: str, admin_distance: str = '', protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Agrega una ruta estática.
    """
    command = f'ip route {network} {subnet_mask} {next_hop}'
    if admin_distance:
        command += f' {admin_distance}'
    
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        connection.send_command(command)
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Ruta {network}/{subnet_mask} -> {next_hop} agregada exitosamente"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error agregando ruta: {str(e)}"

def delete_route(ip: str, username: str, password: str, network: str, subnet_mask: str, next_hop: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Elimina una ruta estática.
    """
    command = f'no ip route {network} {subnet_mask} {next_hop}'
    
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.config_mode()
        connection.send_command(command)
        connection.exit_config_mode()
        connection.disconnect()
        
        return True, f"Ruta {network}/{subnet_mask} -> {next_hop} eliminada exitosamente"
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error eliminando ruta: {str(e)}"

# ==================== FUNCIONES DE SISTEMA ====================

def save_config(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Guarda la configuración actual.
    """
    success, output = execute_command(ip, username, password, 'write memory', protocol)
    
    if success:
        return True, "Configuración guardada exitosamente"
    else:
        return False, f"Error guardando configuración: {output}"

def reboot_router(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, str]:
    """
    Reinicia el router.
    """
    conn_result = _create_connection(ip, username, password, protocol)
    
    if conn_result["status"] != "success":
        return False, conn_result["message"]
    
    try:
        connection = conn_result["connection"]
        connection.enable()
        connection.send_command('reload', expect_string=r'[confirm]')
        connection.send_command('\n')  # Confirmar
        connection.disconnect()
        
        return True, "Router reiniciándose..."
        
    except Exception as e:
        try:
            connection.disconnect()
        except:
            pass
        return False, f"Error reiniciando router: {str(e)}"

# ==================== FUNCIONES DE VALIDACIÓN ====================

def validate_ip_address(ip: str) -> bool:
    """
    Valida formato de dirección IP.
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_subnet_mask(mask: str) -> bool:
    """
    Valida formato de máscara de subred.
    """
    try:
        # Validar formato dotted decimal
        parts = mask.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        
        return True
    except ValueError:
        return False

def get_device_info(ip: str, username: str, password: str, protocol: str = 'telnet') -> Tuple[bool, Dict, str]:
    """
    Obtiene información básica del dispositivo.
    
    Returns:
        Tuple[bool, Dict, str]: (éxito, info_dispositivo, mensaje)
    """
    success, version_output = execute_command(ip, username, password, 'show version', protocol)
    
    if not success:
        return False, {}, version_output
    
    device_info = {
        'ip': ip,
        'protocol': protocol.upper(),
        'model': 'Unknown',
        'ios_version': 'Unknown',
        'uptime': 'Unknown',
        'serial': 'Unknown'
    }
    
    # Extraer información del output
    lines = version_output.split('\n')
    for line in lines:
        if 'Cisco' in line and 'processor' in line:
            device_info['model'] = line.strip()
        elif 'Version' in line and 'IOS' in line:
            device_info['ios_version'] = line.strip()
        elif 'uptime is' in line:
            device_info['uptime'] = line.strip()
        elif 'Processor board ID' in line:
            parts = line.split()
            if len(parts) >= 4:
                device_info['serial'] = parts[3]
    
    return True, device_info, "Información del dispositivo obtenida exitosamente"