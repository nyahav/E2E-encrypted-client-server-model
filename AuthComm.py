from Definitions import *


class Request:
    
    def __init__(self):
        self.version = 24 
    header = struct.Struct(
        "!<I2I"  #  Version, Code, Payload size
    )
  
    @classmethod
    def pack(cls, version, code, payload):
        header_data = cls.header.pack(
            version, code, len(payload)
        )
        return header_data + payload
    
    
    def REGISTER_SUCCESS_RESP(self):
        client_ID="client_ID"
        payload = client_ID.encode() # Encode strings as bytes,defult is UTF-8
        payload_size=len(payload) 
        request_data = Request.pack(self.version, 1600, payload_size,payload)
        
    def REGISTER_FAILURE_RESP(self):
        client_ID="client_ID"
        payload = client_ID.encode()
        payload_size=len(payload) 
        request_data = Request.pack(self.version, 1601, payload_size,payload)
        
    def RESPONSE_MESSAGE_SERVERS(self):
        server_ID="server_ID"
        payload = server_ID.encode()
        payload_size=len(payload) 
        request_data = Request.pack(self.version, 1602, payload_size,payload)
        #list may containe many server,can be calculate by :Payload Size/(16+255)
        
    def  RESPONSE_SYMETRIC_REQ(self):
        client_ID="client_ID"
        AES_symetric_key="AES_symetric_key"
        ticket="ticket"
        payload = client_ID.encode()+AES_symetric_key.encode()+ticket.encode() 
        payload_size=len(payload) 
        request_data = Request.pack((self.version, 1603, payload_size,payload)    
        
        
    REGISTER_SUCCESS_RESP = 1600,
    REGISTER_FAILURE_RESP = 1601,
    RESPONSE_MESSAGE_SERVERS=1602,
    RESPONSE_SYMETRIC_REQ = 1603,