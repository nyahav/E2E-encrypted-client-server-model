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
    
def REGISTER_SERVER():
        username="name"
        AES_symetric_key="AES_symetric_key"
        payload = username.encode() + AES_symetric_key.encode()  # Encode strings as bytes
        payload_size=len(payload)
        request_data = Request.pack(client_id, version, 1027, payload_size,payload)
     
def REQUEST_MESSAGE_SERVERS():
         request_data = Request.pack(client_id, version, 1026, 0)
     
def GET_SYMETRIC_REQ():
        client_ID="client_ID"
        server_ID="server_ID"
        nonce="8bits of random value"
        payload = client_ID.encode() + server_ID.encode()+nonce.encode()  # Encode strings as bytes
        payload_size=len(payload)
        request_data = Request.pack(client_id, version, 1028, payload_size,payload) 