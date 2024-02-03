from Definitions import VERSION, Request
import struct
from enum import Enum
HEADER_SIZE = "<16sHHI"
class Code(Enum):
    REGISTER_REQUEST

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
          
    def register_server(self, username, AES):
        payload = username.encode() + AES
        # Pack the header with client_id, version, and the length of the payload
        header = struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, 1025, len(payload))
        # Concatenate the header and the payload
        request_data = header + payload
        return request_data
        
    def approve_aes_recived(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, 1604, 0) 
        return request_data
    def approve_message_recived(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, 1605, 0) 
        return request_data
    def general_error(self):
        request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, VERSION, 1609, 0) 
        return request_data