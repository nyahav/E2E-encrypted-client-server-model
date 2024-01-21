from Definitions import Request
import struct

HEADER_SIZE = "<16sHHI"

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
    
    class MyRequest(Request):
        
        def register_server(self,username,AES):
            payload = username.encode() + AES.encode()  
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1027, len(self.payload),payload)
            return request_data
     
        def request_message_servers(self):
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1026, 0) 
            return request_data
        
        def get_symetric_req(self,client_ID,server_ID,nonce):
            payload = client_ID.encode() + server_ID.encode()+nonce.encode()
            request_data =struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1028,len(self.payload),payload)
            return request_data
        
        def approve_aes_recived(self):
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1604, 0) 
            return request_data
        def approve_message_recived(self):
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1605, 0) 
            return request_data
        def general_error(self):
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_id, self.version, 1609, 0) 
            return request_data
