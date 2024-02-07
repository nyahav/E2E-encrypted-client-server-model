from Definitions import Request, VERSION,ClientRequestToAuth, RequestMessage,Headers
import struct
import socket


Header_size="<16sHHI"
class SpecificRequest(Request):
    def __init__(self,auth_server_ip, auth_server_port):
        super().__init__()
        self.auth_server_ip = auth_server_ip
        self.auth_server_port = auth_server_port
    

    def register_client(self, username, password):
        payload = username.encode() + password.encode()
        header = struct.pack(Header_size, b'\0', VERSION, ClientRequestToAuth.REGISTER_CLIENT, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def request_message_server(self):
        header = struct.pack(Headers.CLIENT_FORMAT.value, self.client_ID.encode(), VERSION, ClientRequestToAuth.REQUEST_LIST_OF_MESSAGE_SERVERS, 0)
        request_data = header  # No payload for this request
        response = self.send_request(request_data)
        return response

    def request_aes_key_from_auth(self, client_ID, server_ID, nonce):
        payload = client_ID.encode() + server_ID.encode() + nonce.encode()
        header = struct.pack(Headers.CLIENT_FORMAT.value, self.client_ID.encode(), VERSION, ClientRequestToAuth.GET_SYMETRIC_KEY, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def sending_aes_key_to_message_server(self, authenticator, ticket):
        payload = authenticator.encode() + ticket.encode()
        header = struct.pack(Headers.CLIENT_FORMAT.value, self.client_ID.encode(), VERSION, RequestMessage.SEND_SYMETRIC_KEY, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def sending_message_to_message_server(self, message_Size, iv, message_content):
        payload = message_Size.encode() + iv.encode() + message_content.encode()
        header = struct.pack(Headers.CLIENT_FORMAT.value, self.client_ID.encode(), VERSION, RequestMessage.SEND_MESSAGE, len(payload))
        request_data = header + payload
        response = self.send_request(request_data)
        return response

    def send_request(self, request_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.auth_server_ip, self.auth_server_port))
            client_socket.sendall(request_data)
            response_data = client_socket.recv(1024)

        response = self.unpack_response(response_data)
        return response
