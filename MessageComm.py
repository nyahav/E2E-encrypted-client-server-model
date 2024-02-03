from Definitions import VERSION, Request
import struct

HEADER_SIZE = "<16sHHI"

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
    
    class MyRequest(Request):
        
        def register_server(self,username,AES):
            payload = username.encode() + AES.encode()  
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_id,VERSION, 1027, len(self.payload),payload)
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
