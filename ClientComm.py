from Definitions import Request,VERSION
import struct
import socket


HEADER_SIZE="<16sHHI"

class SpecificRequest(Request):
    def __init__(self, auth_server_address, auth_server_port):
        super().__init__()
        self.auth_server_address = auth_server_address
        self.auth_server_port =auth_server_port

    
    class MyRequest(Request):
        my_request_instance = None
        def __init__(self, auth_server_address, auth_server_port):
            # Initialize the instance only if it's not created yet
            if not self.my_request_instance:
                self.my_request_instance = self
                super().__init__(auth_server_address, auth_server_port)
                
        @staticmethod
        def register_client(username,password):
            # problem here
            encoded_username = username.encode()
            encoded_password = password.encode()

            # Pad encoded username and password to a length of 255 bytes with spaces
            padded_username = encoded_username + b'\x00' * (255 - len(encoded_username))
            padded_password = encoded_password + b'\x00' * (255 - len(encoded_password))

            payload = padded_username + padded_password
            request_data = struct.Struct(HEADER_SIZE).pack(str(0).encode(), VERSION, 1024, len(payload))
            request_data = request_data+payload
            return request_data


        @staticmethod
        def request_message_server_list(client_id):
            request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, 1026,0)
            return request_data

        @staticmethod
        def request_aes_key_from_auth(self,client_id,server_id,nonce):
            payload = bytes.fromhex(server_id) + nonce
            request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, 1027, len(payload))
            request_data = request_data+payload
            return request_data

        @staticmethod
        def sending_aes_key_to_message_server(client_id, payload):
            request_data = struct.Struct(HEADER_SIZE).pack(client_id, VERSION, 1028, len(payload))
            request_data += payload
            return request_data

        @staticmethod
        def sending_message_to_message_server(client_id,message_size,iv,message_content):
            payload = message_size.encode()+iv.encode()+message_content
            request_data = struct.Struct(HEADER_SIZE).pack(client_id,VERSION, 1029,len(payload))
            request_data += payload
            return request_data
            
