from Definitions import VERSION, Request, ResponseMessage, MessageServerToAuth
import struct
from enum import Enum
HEADER_SIZE = "<16sHHI"

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
          
    def register_server(self, server_id, username, AES):
        server_id = server_id.encode('utf-8')
        payload = username.encode() + AES
        # Pack the header with client_id, version, and the length of the payload
        header = struct.Struct(HEADER_SIZE).pack(server_id, VERSION, MessageServerToAuth.REGISTER_MESSAGE_SERVER, len(payload))
        # Concatenate the header and the payload
        request_data = header + payload
        return request_data
        
    def approve_aes_recived(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, ResponseMessage.APPROVE_SYMETRIC_KEY, 0) 
        return request_data
    def approve_message_recived(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, ResponseMessage.APPROVE_MESSAGE_RECIVED, 0) 
        return request_data
    def general_error(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, ResponseMessage.GENERAL_ERROR, 0) 
        return request_data