from Definitions import *

class Request:
    def __init__(self):
        self.version = 24
        self.client_ID = "default"

    header = struct.Struct(
        "!<II2I"  # Client ID, Version, Code, Payload size
    )

    @classmethod
    def pack(cls, client_id, version, code, payload):
        header_data = cls.header.pack(
            client_id, version, code, len(payload)
        )
        return header_data + payload

    def REGISTER_CLIENT(self):
        username = "name"
        password = "password"
        payload = username.encode() + password.encode()  # Encode strings as bytes
        payload_size = len(payload)
        request_data = Request.pack(self.client_ID, self.version, 1025, payload_size, payload)

    def REGISTER_SERVER(self):
        username = "name"
        AES_symetric_key = "AES_symetric_key"
        payload = username.encode() + AES_symetric_key.encode()  # Encode strings as bytes
        payload_size = len(payload)
        request_data = Request.pack(self.client_ID, self.version, 1027, payload_size, payload)

    def REQUEST_MESSAGE_SERVERS(self):
        request_data = Request.pack(self.client_ID, self.version, 1026, 0)

    def GET_SYMETRIC_REQ(self):
        client_ID = "client_ID"
        server_ID = "server_ID"
        nonce = "8bits of random value"
        payload = (
            client_ID.encode() + server_ID.encode() + nonce.encode()  # Encode strings as bytes
        )
        payload_size = len(payload)
        request_data = Request.pack(self.client_ID, self.version, 1028, payload_size, payload)
