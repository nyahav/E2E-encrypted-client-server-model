import secrets
import time
import uuid
import ClientComm
import AutoServer
import MessageServer
from Definitions import *


class Client:
    def __init__(self):
        ip_address, port = self.read_client_info()
        self.auth_server_address = ip_address
        self.auth_server_port = port
        self.client_ID, self.clientName, self.client_aes_key = self.read_client_info()
        self.ticket = None
        self.request_instance = ClientComm.SpecificRequest(client_address=ip_address,client_port=port)



    def read_client_info(self):
        try:
            with open("me.info", "r") as file:
                address = file.readline().strip()
                ip_address, port_str = address.split(':')
                port = int(port_str)
                
                clientName = file.readline().strip()
                client_ID = file.readline().strip()
                return client_ID, clientName, ip_address,port
        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def register_with_auth_server(self):
        # Create a request object
        username = input("Enter username: ")
        password = input("Enter password: ")
        request_data = self.request_instance.register_client(username, password)

        # Send the request to the authentication server and receive the response
        self.request_instance = ClientComm.SpecificRequest(self.auth_server_address, self.auth_server_port)
        response = self.request_instance.send_request(request_data)

        if response['Code'] != 1600:
            print("Error: Registration failed.")
            return

        # Save the client ID
        self.client_id = response['Payload']['client_id']
        print("Registration successful.")

    def parse_server_list(self, payload):
        server_list = []
        index = 0

        # Iterate over the payload to extract server information
        while index < len(payload):
            # Unpack the server information (server ID and server name)
            server_info_size = struct.calcsize("<B255s")
            server_info_data = payload[index:index + server_info_size]
            server_id, server_name = struct.unpack("<B255s", server_info_data)

            # Move the index to the next server information
            index += server_info_size

            # Use server_id as a key and create a tuple with server name and IP
            server_list.append({
                'server_id': server_id,
                'server_info': (server_name.decode().rstrip('\x00'), f"192.168.1.{server_id}")  # Replace with actual IP logic
            })

        return server_list

    def request_server_list(self):
        #Requests the list of servers from the authentication server.
        request_data = self.request_instance.request_message_server(self)
        
        # Send the request to the authentication server
        response = self.send_request(request_data)
        payload = self.parse_server_list(response)
        # list may contain many servers, can be calculated by: Payload Size / (1 + 255)
        # Process the response, assuming it contains a list of servers
        server_list = payload  # Assuming payload holds the server list
        # Do something with the server list here
        return server_list

    
    def request_aes_key(self,client_ID, server_ID):
    #Requests an AES key from the authentication server for a specific server.
        nonce_length = 8
        nonce=secrets.token_bytes(nonce_length)
        request_data=self.request_instance.request_aes_key(self,client_ID,server_ID,nonce)
        
        # Send the request to the authentication server
        response = self.request_instance.send_request(request)
        # Process the response, assuming it contains the AES key
        aes_key = response.payload  # Assuming payload holds the AES key
        # Store or use the AES key for communication with the specified server

    def sending_aes_key_to_message_server(self,client_ID,server_ID):
        timeStamp=time.time()
        #authenticator inculde:version,clientID,serverID,timestamp.all of them are encrypted by the symeric key of the reciver.
        authenticator=
        ticket=
        request_data=self.request_instance.request_aes_key(self,authenticator,ticket)
        
    def messaging_the_message_server(self,iv):
        # TODO: Implement communication with the message server using the obtained AES key
        
        message = input("Enter your message: ")
        #need to implement a function to enctypt the message using a symetric key created by the Authentication server
        encrypted_message=
        request_data=self.request_instance.request_aes_key(self,len(encrypted_message),iv,encrypted_message)
        pass

if __name__ == "__main__":
    client = Client()
    client.register_with_auth_server()
    client.request_server_list()
    client.request_aes_key()
    client.sending_aes_key_to_message_server()
    client.messaging_the_message_server()
    
