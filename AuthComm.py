from Definitions import Request
import struct

HEADER_SIZE = "<HHI"

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
    
    class MyRequest(Request):
        
        def register_client_success(self,client_ID):
            payload = client_ID.encode() 
            request_data = struct.Struct(HEADER_SIZE).pack(self.version, 1600, len(self.payload),payload)
            return request_data
            
        def register_client_failure(self,client_ID):
            
            request_data = struct.Struct(HEADER_SIZE).pack(self.version, 1601, 0,0)
            return request_data    
   
        def response_message_servers(self,server_ID,server_name):
            payload = server_ID.encode()+server_name.encode()
            request_data = struct.Struct(HEADER_SIZE).pack(self.version, 1602, len(self.payload),payload)
            return request_data    
            #list may containe many server,can be calculate by :Payload Size/(16+255)
        
        def response_symetric_req(self,client_ID,AES,ticket):
              payload = client_ID.encode()+AES.encode()+ticket.encode() 
              request_data = Request.pack(self.version, 1603,len(self.payload),payload) 
              return request_data
            
            
        