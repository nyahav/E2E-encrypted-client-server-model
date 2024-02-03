from Definitions import Request, VERSION
import struct
import socket

HEADER_SIZE = "<16sHHI"  # Format string for struct

class SpecificRequest(Request):
    def __init__(self, auth_server_address, auth_server_port):
        super().__init__()
        self.auth_server_address = auth_server_address
        self.auth_server_port = auth_server_port
        self.client_ID = None  # You need to set this to a valid value

    def register_client(self, username, password):
        payload = username.encode() + password.encode()
        header = struct.pack(HEADER_SIZE, self.client_ID.encode(), VERSION, 1024, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def request_message_server(self):
        header = struct.pack(HEADER_SIZE, self.client_ID.encode(), VERSION, 1026, 0)
        request_data = header  # No payload for this request
        response = self.send_request(request_data)
        return response

    def request_aes_key_from_auth(self, client_ID, server_ID, nonce):
        payload = client_ID.encode() + server_ID.encode() + nonce.encode()
        header = struct.pack(HEADER_SIZE, self.client_ID.encode(), VERSION, 1027, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def sending_aes_key_to_message_server(self, authenticator, ticket):
        payload = authenticator.encode() + ticket.encode()
        header = struct.pack(HEADER_SIZE, self.client_ID.encode(), VERSION, 1028, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def sending_message_to_message_server(self, message_Size, iv, message_content):
        payload = message_Size.encode() + iv.encode() + message_content.encode()
        header = struct.pack(HEADER_SIZE, self.client_ID.encode(), VERSION, 1029, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def send_request(self, request_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.auth_server_address, self.auth_server_port))
            client_socket.sendall(request_data)
            response_data = client_socket.recv(1024)

        response = self.unpack_response(response_data)
        return response
