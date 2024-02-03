import secrets
import socket
import time
import ClientComm
from Definitions import *
from basicFunctions import *


class Client:
    def __init__(self,auth_server_ip, auth_server_port, message_server_ip, message_server_port):
      
        self.client_ID, self.clientName, self.client_aes_key,self.ip_address, self.port = self.read_client_info()
        self.auth_server_address = self.ip_address
        self.auth_server_port = self.port
        server_list=""
        self.ticket = None
        self.request_instance = ClientComm.SpecificRequest(client_address=self.ip_address,client_port=self.port)
        #connections
        self.auth_server_ip = auth_server_ip
        self.auth_server_port = auth_server_port
        self.message_server_ip = message_server_ip
        self.message_server_port = message_server_port

        # Create persistent connections
        self.auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.auth_sock.connect((self.auth_server_ip, self.auth_server_port))
        self.message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.message_sock.connect((self.message_server_ip, self.message_server_port))

    def read_client_info(self):
        try:
            with open("me.info", "r") as file:
                address = file.readline().strip()
                parts = address.split(':')
                
                if len(parts) != 2:
                    raise ValueError("Invalid address format in me.info file")

                ip_address, port_str = parts
                port = int(port_str)

                clientName = file.readline().strip()
                client_ID = file.readline().strip()
                return client_ID, clientName, ip_address, port
        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def register_with_auth_server(self):
            #take this out to anouther function to combine with read_client_info
            
            username = input("Enter username: ")
            password = input("Enter password: ")

            # Add null terminator if missing
            if username[-1] != '\0':
                username += '\0'
            if password[-1] != '\0':
                password += '\0'

            # Validate username
            if len(username) < 5 or len(username) > 30:
                raise ValueError("Username must be between 5 and 30 characters long.")
            if not username.isalnum():
                raise ValueError("Username must consist only of alphanumeric characters.")

            # Validate password
            if len(password) < 8 or len(password) > 30:
                raise ValueError("Password must be between 8 and 30 characters long.")
            if not password.isalnum():
                raise ValueError("Password must consist only of alphanumeric characters.")

         
            salted_username = username + '\0' * (255 - len(username))
            salted_password = username + '\0' * (255 - len(username))
        
            request_data = self.request_instance.register_client(salted_username,salted_password)

            # Send the request to the authentication server and receive the response
            self.request_instance = ClientComm.SpecificRequest(self.auth_server_address, self.auth_server_port)
            response = self.request_instance.send_request(request_data)
               #/not need to be hard coded
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
        request_data = self.request_instance.request_message_server(self)
        send_request(self.auth_sock, request_data)
        response = receive_response(self.auth_sock)
        payload = self.parse_server_list(response)
        server_list = payload
        return server_list

    def prompt_user_for_server_selection(server_list):
        """Prompts the user to select a server from the provided list and validates their choice."""

        while True:
            print("Available servers:")
            for i, server in enumerate(server_list):
                print(f"{i + 1}. {server['server_name']} ({server['server_id']})")

            try:
                user_selection = int(input("Enter the number of the server you want to connect to: ")) - 1
                selected_server_id = server_list[user_selection]['server_id']
                return selected_server_id
            except (IndexError, ValueError):
                print("Invalid selection. Please enter a valid server number.")

    def request_aes_key(self, client_ID, server_ID):
    #Requests an AES key from the authentication server for a specific server.

        nonce_length = 8
        nonce = secrets.token_bytes(nonce_length)
        request_data = self.request_instance.request_aes_key(self, client_ID, server_ID, nonce)

        # Send the request to the authentication server
        response = self.request_instance.send_request(request_data)

        # Process the response, assuming it contains the AES key
        self.aes_key = response.payload  # Assuming payload holds the AES key

        # Store or use the AES key for communication with the specified server

    def sending_aes_key_to_message_server(self, client_ID, server_ID, ticket):
        """Sends an authenticator and ticket to the messaging server."""

        time_stamp = time.time()
       
        # Pack the authenticator data using struct
        authenticator_data = struct.pack("<BI16s16sQ",
                                        VERSION,  # Version (1 byte)
                                        client_ID.encode(),  # Client ID (16 bytes)
                                        server_ID.encode(),  # Server ID (16 bytes)
                                        int(time_stamp))  # Creation time (8 bytes)
        authenticator = encrypt_message(authenticator_data, self.messaging_server_key, get_random_bytes(16))

        # Create the request data
        request_data = authenticator + ticket

        return request_data

    def messaging_the_message_server(self, aes_key):
       
        message = input("Enter your message: ")

        # Generate a random 16-byte IV (initialization vector)
        iv = secrets.token_bytes(16)

        # Encrypt the message using AES-CBC mode
        encrypted_message = encrypt_message(message.encode(), aes_key, iv)

        # Prepend the 4-byte message size (assuming little-endian)
        request_data = len(encrypted_message).to_bytes(4, "little") + iv + encrypted_message

        # Send the request data to the message server
        self.request_instance.send_request(request_data)

        encrypted_message = encrypt_message(message, aes_key, iv)  # Assuming `encrypt_message` is defined
        request_data = self.request_instance.request_aes_key(self, len(encrypted_message), iv, encrypted_message)

    def close_connections(self):
        self.auth_sock.close()
        self.message_sock.close()

if __name__ == "__main__":
    client = Client("127.0.0.1", 1234, "127.0.0.1", 5678)  
    client.register_with_auth_server()
    client.request_server_list()
    server_list = client.request_server_list()
    selected_server_id = client.prompt_user_for_server_selection(server_list)
    client.request_aes_key(client.client_id, server_list[selected_server_id]['server_id']) 
    client.sending_aes_key_to_message_server(client.client_id, server_list[selected_server_id]['server_id']) 
    client.messaging_the_message_server(client.aes_key)  
    client.close_connections()