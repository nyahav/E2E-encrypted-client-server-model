import socket
import struct
from Definitions import Request, VERSION, ResponseAuth, HeadersFormat

resp_format = HeadersFormat.AUTH_RESP_HEADER.value


class AuthCommHelper(Request):
    def __init__(self):
        super().__init__()
        # Ensure you have client_server_address and client_server_port attributes

    @staticmethod
    def register_client_success(client_id):
        payload = client_id.bytes
        resp_data = struct.pack(resp_format, VERSION, ResponseAuth.REGISTER_SUCCESS_RESP.value, len(payload))
        resp_data += payload
        return resp_data

    @staticmethod
    def register_server_success(server_id):
        payload = server_id.bytes
        resp_data = struct.pack(resp_format, VERSION, ResponseAuth.REGISTER_SUCCESS_RESP.value, len(payload))
        resp_data += payload
        return resp_data
    @staticmethod
    def register_client_failure():
        request_data = struct.pack(resp_format, VERSION, ResponseAuth.REGISTER_FAILURE_RESP.value, 0)
        return request_data

    @staticmethod
    def response_message_servers(server_id, server_name):
        payload = server_id.encode() + server_name.encode()
        request_data = struct.pack(resp_format, VERSION, ResponseAuth.RESPONSE_MESSAGE_SERVERS.value, len(payload))
        request_data += payload
        return request_data

    @staticmethod
    def response_symmetric_req(client_id, aes_key, ticket):
        payload = client_id.encode() + aes_key.encode() + ticket.encode()
        request_data = struct.pack(resp_format, VERSION, ResponseAuth.RESPONSE_SYMETRIC_KEY.value, len(payload))
        request_data += payload
        return request_data


