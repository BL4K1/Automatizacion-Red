import grpc
import router_pb2
import router_pb2_grpc

class RouterGRPCClient:
    def __init__(self, server_address='localhost:50051'):
        self.channel = grpc.insecure_channel(server_address)
        self.stub = router_pb2_grpc.RouterServiceStub(self.channel)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.channel.close()

    def get_interfaces(self, ip, username, password, protocol='telnet'):
        try:
            request = router_pb2.RouterRequest(
                ip=ip,
                username=username,
                password=password,
                protocol=protocol
            )
            response = self.stub.GetInterfaces(request)
            if response.success:
                return True, response.interfaces, response.message
            else:
                return False, [], response.message
        except grpc.RpcError as e:
            return False, [], f"Error gRPC: {e.details()}"

    def add_user(self, ip, username, password, protocol, new_username, new_password, privilege_level='15'):
        try:
            request = router_pb2.AddUserRequest(
                ip=ip,
                username=username,
                password=password,
                protocol=protocol,
                new_username=new_username,
                new_password=new_password,
                privilege_level=privilege_level
            )
            response = self.stub.AddUser(request)
            return response.success, response.message
        except grpc.RpcError as e:
            return False, f"Error gRPC: {e.details()}"

    def delete_user(self, ip, username, password, protocol, target_username):
        try:
            request = router_pb2.DeleteUserRequest(
                ip=ip,
                username=username,
                password=password,
                protocol=protocol,
                target_username=target_username
            )
            response = self.stub.DeleteUser(request)
            return response.success, response.message
        except grpc.RpcError as e:
            return False, f"Error gRPC: {e.details()}"

    def update_user_password(self, ip, username, password, protocol, target_username, new_password):
        try:
            request = router_pb2.UpdateUserRequest(
                ip=ip,
                username=username,
                password=password,
                protocol=protocol,
                target_username=target_username,
                new_password=new_password
            )
            response = self.stub.UpdateUserPassword(request)
            return response.success, response.message
        except grpc.RpcError as e:
            return False, f"Error gRPC: {e.details()}"
