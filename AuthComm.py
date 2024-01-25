import socket
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
            
        
        def response_symetric_req(self,client_ID,AES,ticket):
              payload = client_ID.encode()+AES.encode()+ticket.encode() 
              request_data = Request.pack(self.version, 1603,len(self.payload),payload) 
              return request_data
            
            
        def send_request(self, request_data):
            # Implement the code for sending a request to the server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                # Connect to the authentication server
                client_socket.connect((self.client_server_address, self.client_server_port))

                # Send the request data
                client_socket.sendall(request_data)

                # Receive the response data
                response_data = client_socket.recv(1024)

            # Unpack the response using the unpack_response method from the Request class
            response = self.unpack_response(response_data)

            return response