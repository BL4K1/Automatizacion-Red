from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
from typing import Dict
import paramiko

def ejecutar_comando(ip: str, usuario: str, password: str, comando: str, tipo_dispositivo: str = 'cisco_ios') -> Dict:
    """
    Ejecuta un comando en un dispositivo remoto utilizando Netmiko.
    Incluye configuración para routers con SSH antiguo.

    Retorna un diccionario con:
    - status: 'ok' o 'error'
    - salida: resultado del comando o mensaje de error
    """
    try:
        # Configuración base del dispositivo
        dispositivo = {
            'device_type': tipo_dispositivo,
            'host': ip,
            'username': usuario,
            'password': password,
            'timeout': 20,  # Aumentar timeout
            'session_timeout': 60,
            'banner_timeout': 15,
            'conn_timeout': 10,
        }

        # Configuración específica para routers con SSH antiguo
        if tipo_dispositivo == 'cisco_ios':
            # Configurar algoritmos SSH antiguos
            dispositivo.update({
                'ssh_config_file': None,  # No usar archivo de configuración SSH
                'allow_agent': False,
                'look_for_keys': False,
                'use_keys': False,
                'key_policy': paramiko.AutoAddPolicy(),
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']
                }
            })

        print(f"Intentando conectar a {ip}...")  # Para depuración

        # Crear conexión con configuración personalizada
        conexion = ConnectHandler(**dispositivo)
        
        # Ejecutar comando
        salida = conexion.send_command(comando, expect_string=r'[>#]')
        conexion.disconnect()

        return {
            "status": "ok",
            "salida": salida
        }

    except NetMikoAuthenticationException:
        return {
            "status": "error",
            "salida": "❌ Error de autenticación. Verifica usuario y contraseña."
        }

    except NetMikoTimeoutException:
        return {
            "status": "error",
            "salida": "⏰ Tiempo de espera agotado. El dispositivo no responde o SSH no está habilitado."
        }

    except Exception as e:
        # Intentar con configuración alternativa para SSH muy antiguo
        if "negotiation" in str(e).lower() or "algorithm" in str(e).lower():
            try:
                print(f"Reintentando con configuración SSH legacy para {ip}...")
                
                # Configuración para SSH muy antiguo
                dispositivo_legacy = {
                    'device_type': tipo_dispositivo,
                    'host': ip,
                    'username': usuario,
                    'password': password,
                    'timeout': 30,
                    'session_timeout': 90,
                    'banner_timeout': 20,
                    'conn_timeout': 15,
                    'allow_agent': False,
                    'look_for_keys': False,
                    'use_keys': False,
                    'ssh_config_file': None,
                }

                conexion = ConnectHandler(**dispositivo_legacy)
                salida = conexion.send_command(comando, expect_string=r'[>#]')
                conexion.disconnect()

                return {
                    "status": "ok",
                    "salida": salida
                }

            except Exception as e2:
                return {
                    "status": "error",
                    "salida": f"⚠️ Error de conexión SSH. El router puede usar algoritmos SSH antiguos no soportados. Error: {str(e2)}"
                }
        else:
            return {
                "status": "error",
                "salida": f"⚠️ Error inesperado: {str(e)}"
            }


def ejecutar_comando_telnet(ip: str, usuario: str, password: str, comando: str) -> Dict:
    """
    Alternativa usando Telnet para routers que no soporten SSH moderno.
    """
    try:
        dispositivo = {
            'device_type': 'cisco_ios_telnet',
            'host': ip,
            'username': usuario,
            'password': password,
            'timeout': 20,
            'session_timeout': 60,
        }

        conexion = ConnectHandler(**dispositivo)
        salida = conexion.send_command(comando, expect_string=r'[>#]')
        conexion.disconnect()

        return {
            "status": "ok",
            "salida": salida
        }

    except Exception as e:
        return {
            "status": "error",
            "salida": f"⚠️ Error Telnet: {str(e)}"
        }