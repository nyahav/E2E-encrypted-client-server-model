import socket
import struct
from Definitions import Request, VERSION, ResponseAuth

HEADER_SIZE = "<HHI"

class SpecificRequest(Request):
    def __init__(self):
        super().__init__()
        # Ensure you have client_server_address and client_server_port attributes

    def register_client_success(self, client_ID):
        payload = client_ID.encode()
        request_data = struct.pack(HEADER_SIZE, VERSION, ResponseAuth.REGISTER_SUCCESS_RESP, len(payload)) + payload
        return request_data

    def register_client_failure(self, client_ID):
        request_data = struct.pack(HEADER_SIZE, VERSION, ResponseAuth.REGISTER_FAILURE_RESP, 0)
        return request_data

    def response_message_servers(self, server_ID, server_name):
        payload = server_ID.encode() + server_name.encode()
        request_data = struct.pack(HEADER_SIZE, VERSION, ResponseAuth.RESPONSE_MESSAGE_SERVERS, len(payload)) + payload
        return request_data

    def response_symetric_req(self, client_ID, AES, ticket):
        payload = client_ID.encode() + AES.encode() + ticket.encode()
        request_data = struct.pack(HEADER_SIZE, VERSION, ResponseAuth.RESPONSE_SYMETRIC_KEY, len(payload)) + payload
        return request_data

    def send_request(self, request_data):
        # Code for sending a request to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Connect to the server
            client_socket.connect((self.client_server_address, self.client_server_port))

            # Send the request data
            client_socket.sendall(request_data)

            # Receive the response data
            response_data = client_socket.recv(1024)

        # Unpack the response using the unpack_response method from the Request class
        response = self.unpack_response(response_data)

        return response
