import secrets
import uuid
import Request
import ClientComm
import AutoServer
import MessageServer
from Definitions import *


class Client:
    def __init__(self):
        ip_address, port = self.read_auth_server_address()
        self.auth_server_address = ip_address
        self.auth_server_port = port
        self.client_id, self.client_name, self.client_aes_key = self.read_client_info()
        self.ticket = None
        self.request_instance = ClientComm.SpecificRequest(auth_server_address=ip_address,auth_server_port=port)

    def read_auth_server_address(self):
        try:
            with open("me.info", "r") as file:
                address_line = file.readline().strip()
                # Split the line into IP address and port number
                ip_address, port_str = address_line.split(':')
                # Convert the port string to an integer
                port = int(port_str)
                # Return both IP address and port
                
                return ip_address, port

        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def read_client_info(self):
        try:
            with open("me.info", "r") as file:
                address = file.readline().strip()
                name = file.readline().strip()
                client_id = file.readline().strip()
                return client_id, name, address
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

    def request_server_list(self):
        #Requests the list of servers from the authentication server.
        request_data=self.request_instance.request_message_server(self)
        
        # Send the request to the authentication server
        response = self.send_request(request)

        # Process the response, assuming it contains a list of servers
        server_list = response.payload  # Assuming payload holds the server list
        # Do something with the server list here

    def request_aes_key(self,client_ID, server_ID):
    #Requests an AES key from the authentication server for a specific server.
        nonce_length = 8
        nonce=secrets.token_bytes(nonce_length)
        request_data=self.request_instance.request_aes_key(self,client_ID,server_ID,nonce)
        
        # Send the request to the authentication server
        response = self.send_request(request)
        # Process the response, assuming it contains the AES key
        aes_key = response.payload  # Assuming payload holds the AES key
        # Store or use the AES key for communication with the specified server


    def communicate_with_message_server(self):
        # TODO: Implement communication with the message server using the obtained AES key
        pass

if __name__ == "__main__":
    client = Client()
    client.register_with_auth_server()
    client.request_server_list()
    client.request_aes_key()
    client.communicate_with_message_server()
    #SADASD
