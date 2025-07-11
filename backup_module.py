from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
import datetime
import os

def obtener_backup(ip, usuario, password, tipo_dispositivo='cisco_ios', comando='show running-config'):
    """
    Conecta a un dispositivo de red y guarda el resultado del comando como backup.
    Retorna un diccionario con estado y detalles del resultado.
    """
    try:
        # Asegura que el directorio 'backups' existe
        os.makedirs("backups", exist_ok=True)

        # Define los parámetros de conexión
        dispositivo = {
            'device_type': tipo_dispositivo,
            'host': ip,
            'username': usuario,
            'password': password,
        }

        print(f"Conectando a {ip}...")  # Para depuración o logs

        # Conexión al dispositivo
        conexion = ConnectHandler(**dispositivo)
        
        # Ejecuta el comando especificado
        config = conexion.send_command(comando)
        conexion.disconnect()

        # Construye nombre de archivo con fecha/hora
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        nombre_archivo = f"backup_{ip}_{timestamp}.txt"
        ruta_archivo = os.path.join('backups', nombre_archivo)

        # Guarda la configuración en archivo
        with open(ruta_archivo, 'w', encoding='utf-8') as f:
            f.write(config)

        # Retorna éxito
        return {
            "status": "ok",
            "archivo": nombre_archivo,
            "ruta": ruta_archivo
        }

    except NetMikoAuthenticationException:
        return {"status": "error", "mensaje": "Error de autenticación con el dispositivo"}

    except NetMikoTimeoutException:
        return {"status": "error", "mensaje": "Tiempo de espera agotado al conectar con el dispositivo"}

    except Exception as e:
        return {"status": "error", "mensaje": f"Error inesperado: {str(e)}"}
