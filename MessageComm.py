from Definitions import VERSION, Request, ResponseMessage, MessageServerToAuth, HeadersFormat
import struct
from enum import Enum
import uuid

HEADER_SIZE = HeadersFormat.MESSAGE_FORMAT.value
auth_resp_form = HeadersFormat.AUTH_RESP_HEADER.value


class SpecificRequest(Request):
    def __init__(self):
        super().__init__()

    @staticmethod
    def register_server(server_id, server_name, aes_key, port):
        payload = server_name.encode().ljust(255) + aes_key + struct.pack('<H', port)
        # Pack the header with client_id, version, and the length of the payload
        header = struct.Struct(HEADER_SIZE).pack(server_id, VERSION, MessageServerToAuth.REGISTER_MESSAGE_SERVER,
                                                 len(payload))
        # Concatenate the header and the payload
        request_data = header + payload
        return request_data

    @staticmethod
    def approve_aes_receive(client_id):
        request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, ResponseMessage.APPROVE_SYMETRIC_KEY, 0)
        return request_data

    @staticmethod
    def approve_message_receive(client_id):
        request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, ResponseMessage.APPROVE_MESSAGE_RECIVED,
                                                       0)
        return request_data

    @staticmethod
    def general_error(client_id):
        request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, ResponseMessage.GENERAL_ERROR, 0)
        return request_data

    @staticmethod
    def unpack_register_message_success(request_data):
        header_size = struct.calcsize(auth_resp_form)
        version, response_type, payload_length = struct.unpack(auth_resp_form, request_data[:header_size])
        message_id_bytes = request_data[header_size:header_size + payload_length]
        message_id = message_id_bytes.decode()
        return version, response_type, message_id
