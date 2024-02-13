import base64
import hashlib
import os
import time
import uuid
import socket
import threading
from datetime import datetime

import Definitions
from Definitions import *
from MessageServer import MessageServer
from basicFunctions import EncryptionHelper
from AuthComm import AuthCommHelper


# client list need to be global
class AuthenticationServer:
    def __init__(self):
        self.encryption_helper = EncryptionHelper()
        self.port = self.encryption_helper.get_auth_port_number()
        self.clients = {}
        self.servers = {}
        self.read_server_list(Definitions.SERVERS_FILE)
        self.load_clients()

    def read_server_list(self, file_path):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) == 4:
                        ip_port, server_id, server_name, message_aes_key = parts
                        ip, port = ip_port.split(':')

                        self.servers[server_id] = {
                            'ip': ip,
                            'port': port,
                            'server_name': server_name,
                            'message_AES_key': message_aes_key
                        }
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def write_server_list(self, file_path):
        try:
            with open(file_path, 'w') as file:
                for server_id, server_info in self.servers.items():
                    ip_port = f"{server_info['ip']}:{server_info['port']}"
                    line = f"{ip_port},{server_id},{server_info['server_name']},{server_info['message_AES_key']}\n"
                    file.write(line)
        except IOError as e:
            print(f"An error occurred while writing to the file: {e}")

    def add_message_server(self, server_name, message_aes_key, port):

        server_id = uuid.uuid4().hex  # binary form of server_id
        # Python script to open the file named 'ExampleServer.txt' and read the first line

        # Open the file in read mode

        self.servers[server_id] = {
            'ip': '127.0.0.1',
            'port': port,
            'server_name': server_name,
            'message_AES_key': message_aes_key
        }
        self.write_server_list(Definitions.SERVERS_FILE)
        return server_id

    def load_clients(self):
        # Load client information from file (if exists)
        valid_entry_found = False  # Flag to track if any valid entries have been found
        try:
            with open("clients.info", "r") as file:
                lines = file.readlines()

                if lines:
                    for line in lines:
                        line = line.strip()
                        if line:  # Check if the line is not empty
                            client_data = line.split(":")
                            if len(client_data) == 4:
                                client_id, name, password_hash, last_seen = client_data
                                self.clients[client_id] = {"name": name, "password_hash": password_hash,
                                                           "last_seen": last_seen}
                                valid_entry_found = True  # Set the flag to True for valid entry
                            else:
                                print(f"Invalid format in clients.info: {line}")
                else:
                    print("File clients.info is empty.")

            # Print the "Invalid format" message only if no valid entry has been found
            if not valid_entry_found:
                print("No valid entries found in clients.info.")
        except FileNotFoundError:
            pass  # File doesn't exist yet

    def handle_client_requests(self, client_socket):
        try:
            auth_comm_helper = ResponseAuth
            response_data = None
            request_type = None
            client_address, client_port = client_socket.getpeername()

            while True:  # Keep the connection open until the client disconnects
                # Receive the request from the client
                request_data = client_socket.recv(1024)
                if not request_data:
                    break  # If no data is received, break the loop and close the connection

                header, payload = self.encryption_helper.unpack(HeadersFormat.CLIENT_FORMAT.value, request_data)
                request_type = header[Header.CODE.value]
                request_client_id = header[Header.CLIENT_ID.value]

                # Use a switch case or if-elif statements to handle different request types
                if request_type == ClientRequestToAuth.REGISTER_CLIENT:
                    response_data = self.handle_client_connection(payload)

                elif request_type == ClientRequestToAuth.REQUEST_LIST_OF_MESSAGE_SERVERS:
                    response_data = self.handle_request_server_list_()

                elif request_type == ClientRequestToAuth.GET_SYMETRIC_KEY:
                    response_data = self.handle_request_get_aes_key(payload,request_client_id)


                elif request_type == MessageServerToAuth.REGISTER_MESSAGE_SERVER:
                    message_server_payload_format = '<255s32sH'
                    # Unpack the data
                    server_name, aes_key, port = struct.unpack(message_server_payload_format, payload)

                    # Decode the server name to a string if necessary (assuming UTF-8 encoding, adjust as needed)
                    server_name = server_name.decode('utf-8').rstrip('\x00').strip()  # Removing potential null padding
                    aes_key = base64.b64encode(aes_key).decode('utf-8')

                    new_server_id = self.add_message_server(server_name, aes_key, port)
                    response_data = AuthCommHelper.register_server_success(new_server_id)
                else:
                    response_data = ResponseMessage.GENERAL_ERROR.value

                # Ensure that the response_data is encoded before sending
                client_socket.send(response_data)

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()

    def save_registered_servers(self):
        # Save registered servers to file
        with open("server.txt", "w") as file:
            for server_id, server_info in self.server.items():
                file.write(f"{server_id}:{server_info['name']}:{server_info['aes_key']}\n")

    def handle_client_connection(self, payload, last_seen=None):
        payload_format = '255s255s'
        username, password = struct.unpack(payload_format, payload)

        # Remove padding from username and password
        username = username.rstrip(b'\x00').decode('utf-8')
        password = password.rstrip(b'\x00').decode('utf-8')
        print("Username:", username)
        print("Password:", password)

        if self.check_username_exists(username):
            return (ResponseAuth.REGISTER_FAILURE_RESP)
        client_id = uuid.uuid4().hex
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        last_seen = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if last_seen is None else last_seen
        self.save_client_info(username, client_id, hashed_password, last_seen)
        response = AuthCommHelper.register_client_success(client_id)
        print(response)
        return response

    def check_username_exists(self, username):
        # Check if the username already exists in the clients.info file
        with open("clients.info", "r") as file:
            for line in file:
                if line.strip().split(',')[0] == username:
                    return True
        return False

    def save_client_info(self, username, client_id, hashed_password, last_seen):
        # Save client information to clients.info file
        with open("clients.info", "a") as file:
            file.write(f"{username},{client_id},{hashed_password}:{last_seen}\n")

    def handle_request_server_list_(self):
        modified_server_list = []
        for server_id, server_info in self.servers.items():
            # Extract IP and port from ip_port
            ip = server_info['ip']
            port = server_info['port']

            # Construct the modified server dictionary
            modified_server = {
                'server_name': server_info['server_name'],
                'ip': ip,
                'port': port,
                'server_id': server_id
            }
            modified_server_list.append(modified_server)

        print(modified_server_list)
        """     
        server_list = [
          {'ip': '192.168.1.1', 'port': 8000, 'server_id': '123', 'server_name': 'Server1', 'message_AES_key': 'AES_KEY1'},
          {'ip': '192.168.1.2', 'port': 9000, 'server_id': '456', 'server_name': 'Server2', 'message_AES_key': 'AES_KEY2'},
          ]
        """

        response_data = AuthCommHelper.response_message_servers_list(modified_server_list)
        print(response_data)
        return response_data

    def handle_request_get_aes_key(self, request,client_id):
        print("request before encode"+request)
        request = request.decode()
        print("request after encode" + request)


        # Extract server_id (16 bytes)
        server_id_bytes = request[16:32]
        server_id = server_id_bytes.hex()  # Convert bytes to hexadecimal string

        # Extract nonce (8 bytes)
        nonce_bytes = request[32:40]
        nonce = nonce_bytes.hex()

        # Retrieve the client's symmetric key (his hashed password)
        client_key = self.retrieve_hashed_password(client_id)

        # Generate the AES key for the client and server
        aes_key = os.urandom(32)

        # Create the encrypted key for the server
        encrypted_key_iv = os.urandom(16)
        encrypted_key = encrypt_message(aes_key + nonce, client_key, encrypted_key_iv)

        # Create the ticket for the client
        ticket_iv = get_random_bytes(16)
        creation_time = int(time.time())
        expiration_time = creation_time + self.ticket_expiration_time
        ticket_data = struct.pack("<BI16s16sQ16s32sQ",
                                  VERSION,  # Version (1 byte)
                                  client_id.encode(),  # Client ID (16 bytes)
                                  server_id.encode(),  # Server ID (16 bytes)
                                  creation_time,  # Creation time (8 bytes)
                                  ticket_iv,  # Ticket IV (16 bytes)
                                  encrypt_message(aes_key, self.messaging_server_key, ticket_iv),
                                  # Encrypted AES key (32 bytes)
                                  expiration_time)  # Expiration time (8 bytes)

        encrypted_ticket = encrypt_message(ticket_data, client_key, get_random_bytes(16))

        return client_id, encrypted_key + encrypted_key_iv, encrypted_ticket

    def retrieve_hashed_password(client_id):
        try:
            # Open the clients.info file in read mode
            with open("clients.info", "r") as file:
                # Iterate through each line in the file
                for line in file:
                    # Split the line into components using comma as delimiter
                    client_info = line.strip().split(",")
                    # Check if the first element (client ID) matches the provided client ID
                    if client_info[1] == client_id:
                        # If found, return the hashed password (second element)
                        return client_info[2]
        except FileNotFoundError:
            # Handle the case where the file is not found
            print("Error: File 'clients.info' not found.")
        # Handle the case where client ID is not found in the file
        print("Client ID not found in the file.")
        return None

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Authentication server listening on port {self.port}...")

        # Consider adding switch case for requests
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_requests, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()


if __name__ == "__main__":
    auth_server = AuthenticationServer()
    auth_server.start()
