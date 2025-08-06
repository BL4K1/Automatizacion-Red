import grpc
from concurrent import futures
import router_pb2
import router_pb2_grpc
from netmiko import ConnectHandler
import time

class RouterService(router_pb2_grpc.RouterServiceServicer):

    def _netmiko_connect(self, ip, username, password, protocol='telnet', secret=None):
        try:
            device = {
                'device_type': 'cisco_ios_telnet' if protocol == 'telnet' else 'cisco_ios',
                'ip': ip,
                'username': username,
                'password': password,
                'secret': 'tu_password_enable',  # usa secret si hay, sino password
            }
            print(f"Intentando conectar a {ip} con usuario {username} vía {protocol}")
            connection = ConnectHandler(**device)
            print("Conectado, intentando enable()")
            connection.enable()
            print("Entró a modo enable")
            return connection
        except Exception as e:
            print(f"Error de conexión Netmiko: {e}")
            return None



    def GetInterfaces(self, request, context):
        net_connect = self._netmiko_connect(request.ip, request.username, request.password, request.protocol)
        if not net_connect:
            return router_pb2.InterfacesResponse(success=False, message="No se pudo conectar", interfaces=[])

        output = net_connect.send_command("show ip interface brief")
        net_connect.disconnect()

        interfaces = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith(("GigabitEthernet", "FastEthernet", "Ethernet")):
                iface = router_pb2.Interface(
                    name=parts[0],
                    ip_address=parts[1],
                    status=parts[4],
                    description=""  # Podrías mejorar esto luego
                )
                interfaces.append(iface)

        return router_pb2.InterfacesResponse(success=True, interfaces=interfaces, message="Interfaces obtenidas correctamente")

    def AddUser(self, request, context):
        conn = self._netmiko_connect(request.ip, request.username, request.password, request.protocol)
        if not conn:
            return router_pb2.OperationResponse(success=False, message="No se pudo conectar")

        commands = [
            f"username {request.new_username} privilege {request.privilege_level or 15} secret {request.new_password}",
            "end",
            "write memory"
        ]
        conn.send_config_set(commands)
        conn.disconnect()

        return router_pb2.OperationResponse(success=True, message=f"Usuario {request.new_username} agregado correctamente")

    def DeleteUser(self, request, context):
        conn = self._netmiko_connect(request.ip, request.username, request.password, request.protocol)
        if not conn:
            return router_pb2.OperationResponse(success=False, message="No se pudo conectar")

        commands = [
            f"no username {request.target_username}",
            "end",
            "write memory"
        ]
        conn.send_config_set(commands)
        conn.disconnect()

        return router_pb2.OperationResponse(success=True, message=f"Usuario {request.target_username} eliminado correctamente")

    def UpdateUserPassword(self, request, context):
        conn = self._netmiko_connect(request.ip, request.username, request.password, request.protocol)
        if not conn:
            return router_pb2.OperationResponse(success=False, message="No se pudo conectar")

        commands = [
            f"username {request.target_username} secret {request.new_password}",
            "end",
            "write memory"
        ]
        conn.send_config_set(commands)
        conn.disconnect()

        return router_pb2.OperationResponse(success=True, message=f"Contraseña de {request.target_username} actualizada correctamente")


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    router_pb2_grpc.add_RouterServiceServicer_to_server(RouterService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Servidor gRPC corriendo en puerto 50051...")
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
