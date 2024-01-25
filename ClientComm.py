from Definitions import Request
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
                
                
        def register_client(self, username, password):
            payload = username.encode() + password.encode()
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1024,len(self.payload), payload)
            response = self.my_request_instance.send_request(request_data)
            return response
            
        def register_server(self,username,AES):
            payload=username.encode()+AES.encode()
            request_data=struct.Struct(HEADER_SIZE).pack(self.client_ID,self.version,1025,len(self.payload),payload)
            response = self.my_request_instance.send_request(request_data)
            return response
            

        def request_message_server(self):
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1026,0,0)
            response = self.my_request_instance.send_request(request_data)
            return response
            

        def request_aes_key_from_auth(self,client_ID,server_ID,nonce):
            payload = client_ID.encode() + server_ID.encode() + nonce.encode() 
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1027,len(self.payload), payload)
            response = self.my_request_instance.send_request(request_data)
            return response
            
        
        def sending_aes_key_to_message_server(self,authenticator,ticket):
            payload=authenticator.encode()+ticket.encode()
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1028,len(self.payload), payload)
            response = self.my_request_instance.send_request(request_data)
            return response
            
        
        def sending_message_to_message_server(self,message_Size,iv,message_content):
            payload=message_Size.encode()+iv.encode()+message_content.encode() 
            request_data = struct.Struct(HEADER_SIZE).pack(self.client_ID, self.version, 1029,len(self.payload), payload)  
            response = self.my_request_instance.send_request(request_data)
            return response
            
        def send_request(self, request_data):
            # Implement the code for sending a request to the server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                # Connect to the authentication server
                client_socket.connect((self.auth_server_address, self.auth_server_port))

                # Send the request data
                client_socket.sendall(request_data)

                # Receive the response data
                response_data = client_socket.recv(1024)

            # Unpack the response using the unpack_response method from the Request class
            response = self.unpack_response(response_data)

            return response