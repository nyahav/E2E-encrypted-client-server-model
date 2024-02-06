import base64
import time
import uuid
import socket
import threading
from Definitions import *
from MessageServer import MessageServer
from basicFunctions import EncryptionHelper


# client list need to be global
class AuthenticationServer:
    def __init__(self):
        self.encryption_helper = EncryptionHelper()
        self.port = self.encryption_helper.get_auth_port_number()
        self.load_registered_servers()
        self.load_clients()
        self.clients = {}
        self.servers = {}

    def read_server_list(self, file_path):
        server_list = []

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()

                for line in lines:
                    # Splitting the line into IP:Port and name
                    ip_port, name = map(str.strip, line.split(','))
                    ip, port = ip_port.split(':')

                    # Creating a new server object and setting the attributes
                    server = MessageServer(len(server_list) + 1)
                    server.IP = ip
                    server.port = int(port)
                    server.server_name = name

                    # Reading additional info from the corresponding server info file
                    server.read_server_info()

                    # Adding the server object to the list
                    server_list.append(server)

        except FileNotFoundError:
            pass  # File doesn't exist yet

        return server_list

    def load_registered_servers(self):
        server_list = self.read_server_list("msg_server_list.info")
        for server in server_list:
            self.servers[server.server_num] = {
                "name": server.server_name,
                "aes_key": base64.b64encode(server.symmetric_key).decode(),
            }

    def save_servers(self):
        # Save server information to file
        with open("msg_server_list.info", "w") as file:
            for server_id, server_info in self.servers.items():
                server_name = server_info.get("name")
                aes_key = server_info.get("aes_key")

                # Validate required fields
                if not server_id or not server_name or not aes_key:
                    raise ValueError("Missing required server information: (id, name, aes_key)")

                file.write(f"{server_id}:{server_name}:{aes_key}\n")

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
            response_data = None
            request_type = None

            # Receive the request from the client
            request_data = client_socket.recv(1024)
            print(request_data)
            print("reqest data")
            request_type, payload = self.unpack_MessageServer(request_data)
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
                print("message from MessageServer")
                response_data = self.load_registered_servers(payload)

            else:
                response_data = (ResponseMessage.GENERAL_ERROR,)

            # Ensure that the response_data is encoded before sending
            encoded_response_data = self.encryption_helper.serialize_response(response_data)
            client_socket.send(encoded_response_data)

        except Exception as e:
            print(f"Error handling client: {e}")
            response_data = (ResponseMessage.GENERAL_ERROR,)

        finally:
            # Assign the response_data to self.encryption_helper.receive_response
            self.encryption_helper.receive_response = response_data
            client_socket.close()

    def unpack_MessageServer(cls, response_payload):
        # Implement the unpacking logic for the response payload
        header_format = "<16sHHI"
        header_size = struct.calcsize(header_format)
        header = struct.unpack(header_format, response_payload[:header_size])

        request_type = header[2]  # Assuming 'Code' field corresponds to the request type
        payload_size = header[3]
        payload = response_payload[header_size:header_size + payload_size]

        return request_type, payload

    def save_registered_servers(self):
        # Save registered servers to file
        with open("server.txt", "w") as file:
            for server_id, server_info in self.server.items():
                file.write(f"{server_id}:{server_info['name']}:{server_info['aes_key']}\n")

    def handle_client_connection(self, request):
        username = request.payload["username"]
        password = request.payload["password"]

        if username not in self.clients:
            client_id = self.generate_unique_id()
            self.clients[username] = {"client_id": client_id, "password": password}

            response = (ResponseAuth.REGISTER_SUCCESS_RESP, {"client_id": client_id})
        else:
            response = (ResponseAuth.REGISTER_FAILURE_RESP)

        return response

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
