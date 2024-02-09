import base64
import hashlib
import os
import time
import uuid
import socket
import threading
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

        server_id = uuid.uuid4()  # binary form of server_id
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
        try:
            with open("clients.info", "r") as file:
                lines = file.readlines()

                if lines:
                    for line in lines:
                        client_data = line.strip().split(":")
                        if len(client_data) == 4:
                            client_id, name, password_hash, last_seen = client_data
                            self.clients[client_id] = {"name": name, "password_hash": password_hash,
                                                       "last_seen": last_seen}
                        else:
                            print(f"Invalid format in clients.info: {line.strip()}")
                else:
                    print("File clients.info is empty.")
        except FileNotFoundError:
            pass  # File doesn't exist yet

    def save_clients(self):
        # Save client information to file
        with open("clients.info", "w") as file:
            for client_id, client_info in self.clients.items():
                file.write(
                    f"{client_id}:{client_info['name']}:{client_info['password_hash']}:{client_info['last_seen']}\n")

    def handle_client_requests(self, client_socket):
        try:
            auth_comm_helper = ResponseAuth
            response_data = None
            request_type = None
            client_address, client_port = client_socket.getpeername()
            # Receive the request from the client
            request_data = client_socket.recv(1024)
            header, payload = self.encryption_helper.unpack(HeadersFormat.CLIENT_FORMAT.value, request_data)
            request_type = header[Header.CODE.value]
            # Use the updated parse_request function
            # request_type, payload = self.encryption_helper.parse_request(request_data)

            # Use a switch case or if-elif statements to handle different request types
            if request_type == ClientRequestToAuth.REGISTER_CLIENT:
                response_data = self.handle_client_connection(payload)
            elif request_type == ClientRequestToAuth.GET_SYMETRIC_KEY:
                client_id, encrypted_key, encrypted_ticket = self.handle_request_get_aes_key(payload)
                response_data = (ResponseAuth.RESPONSE_SYMETRIC_KEY,
                                 {"client_id": client_id, "encrypted_key": encrypted_key,
                                  "encrypted_ticket": encrypted_ticket})
            elif request_type == ClientRequestToAuth.REQUEST_LIST_OF_MESSAGE_SERVERS:
                response_data = self.handle_request_server_list_(client_socket)
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
                response_data = (ResponseMessage.GENERAL_ERROR,)

            # Ensure that the response_data is encoded before sending
            client_socket.send(response_data)

        except Exception as e:
            print(f"Error handling client: {e}")
            response_data = (ResponseMessage.GENERAL_ERROR,)

        finally:
            client_socket.close()

    def save_registered_servers(self):
        # Save registered servers to file
        with open("server.txt", "w") as file:
            for server_id, server_info in self.server.items():
                file.write(f"{server_id}:{server_info['name']}:{server_info['aes_key']}\n")

    def  handle_client_connection(self, payload):
        payload_format = '255s255s'
        username, password = struct.unpack(payload_format, payload)

        # Remove padding from username and password
        username = username.rstrip(b'\x00').decode('utf-8')
        password = password.rstrip(b'\x00').decode('utf-8')
        print("Username:", username)
        print("Password:", password)

        if self.check_username_exists(username):
            return (ResponseAuth.REGISTER_FAILURE_RESP)
        client_id = str(uuid.uuid4())
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.save_client_info(username, client_id, hashed_password)
        response = (ResponseAuth.REGISTER_SUCCESS_RESP, {"client_id": client_id})
        return response


    def check_username_exists(self, username):
        # Check if the username already exists in the clients.info file
        with open("clients.info", "r") as file:
            for line in file:
                if line.strip().split(',')[0] == username:
                    return True
        return False


    def save_client_info(self, username, client_id, hashed_password):
        # Save client information to clients.info file
        with open("clients.info", "a") as file:
            file.write(f"{username},{client_id},{hashed_password}\n")

    def handle_request_get_aes_key(self, request):

        client_id = request.payload["client_id"]
        server_id = request.payload["server_id"]
        nonce = request.payload["nonce"]

        # Retrieve the client's symmetric key (assuming you have a mechanism to store and retrieve it)
        client_key = self.get_client_key(client_id)

        # Generate the AES key for the client and server
        aes_key = get_random_bytes(32)

        # Create the encrypted key for the server
        encrypted_key_iv = get_random_bytes(16)
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

    def handle_request_server_list_(self, sock):
        request = receive_response(sock)  # Receive the request

        # Process the request and generate the server list
        server_list = list(self.servers.values())  # Assuming self.servers is a dictionary of servers
        response_data = self.response_instance.create_server_list_response(server_list)

        send_request(sock, response_data)  # Send the response

    def create_server_list_response(self, server_list):
        response_data = b""
        for server in server_list:
            # Assuming server objects have attributes server_ID and server_name
            server_response = self.response_message_servers(server.server_ID, server.server_name)
            response_data += server_response
        return response_data

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Authentication server listening on port {self.port}...")

        # Consider adding switch case for requests
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_requests, args=(client_socket,))
            client_thread.start()


if __name__ == "__main__":
    auth_server = AuthenticationServer()
    auth_server.start()