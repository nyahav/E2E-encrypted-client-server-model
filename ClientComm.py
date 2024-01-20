from Definitions import Request
import struct


HEADER_SIZE="<16sHHI"

class SpecificRequest(Request):  
    def __init__(self):
        super().__init__()
    
    class MyRequest(Request):
        def register_client(self, username, password):
            payload = username.encode() + password.encode()
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1025,len(self.payload), payload)
            return request_data

        def register_server(self,username,AES):
            payload=username.encode()+AES.encode()
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_ID,self.version,1026,len(self.payload),payload)
            return request_data

        def request_message_server(self):
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1026,0,0)
            return request_data

        def get_symtric_req(self,client_ID,server_ID,nonce):
            payload = client_ID.encode() + server_ID.encode() + nonce.encode() 
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1028,len(self.payload), payload)
            return request_data
