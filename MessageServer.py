import os
import base64
import socket
from Definitions import *
from basicFunctions import *
from MessageComm import SpecificRequest
class MessageServer:
    def __init__(self, mServer_num):
        self.server_num = mServer_num
        self.read_server_info()  # Read info from msg(#).info

    def read_server_info(self):
        with open(f"msg{self.server_num}.info", "r") as f:
            lines = f.readlines()
            if len(lines) >= 4:
                (self.IP, self.port) = lines[0].strip().split(":")
                self.server_name = lines[1].strip()
                self.server_id = bytes.fromhex(lines[2].strip())
                self.symmetric_key = base64.b64decode(lines[3].strip()+'=')
                self.port = int(self.port)

    def write_server_info(self):
        with open(f"msg{self.server_num}.info", "w") as file:
            file.write(f"{self.IP}:{self.port}\n")
            file.write(f"{self.server_name}\n")
            file.write(f"{self.server_id.hex()}\n")
            file.write(f"{base64.b64encode(self.symmetric_key).decode()}\n")

    def handle_client_request(self, client_socket):
        """Handles incoming client requests."""
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = parse_request(request_data)  # Assuming you have a parsing function

            # Handle different request types
            if request.type == RequestMessage.SEND_SYMETRIC_KEY:
                self.receive_aes_key_from_client(client_socket)  
            elif request.type == RequestMessage.SEND_MESSAGE:
                self.receive_message_from_client(client_socket)  
            else:
                response = (ResponseMessage.GENERAL_ERROR,)

            client_socket.send(serialize_response(response))  

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()

    def receive_aes_key_from_client(self, sock, authenticator, ticket):
        # Function to get an AES key from the message server
        ...

    def receive_message_from_client(self, sock):
        # Function to receive a message from the client
        ...

def main():
    r = SpecificRequest()
    mServer_num = 1  # Define your server number or ID here, different for every Thread
    message_server = MessageServer(mServer_num)


    #register this message server to the authentication server
    auth_port_number = get_auth_port_number()
    register_data = r.register_server(message_server.server_id,message_server.server_name, message_server.symmetric_key)
    sign_to_auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_address = ('127.0.0.1', auth_port_number)
    sign_to_auth_sock.connect(auth_address)
    sign_to_auth_sock.send(register_data)


    server_address = (message_server.IP, message_server.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        client_sock, client_address = sock.accept()
        try:
            message_server.handle_client_request(client_sock)
        finally:
            client_sock.close()

if __name__ == "__main__":
    main()
