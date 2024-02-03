import time
import uuid
import socket
import threading
from Definitions import *
from basicFunctions import encrypt_message,get_random_bytes, receive_response, send_request

#client list need to be global
class AuthenticationServer:
    def __init__(self):
       self.port = self.load_port_info()
       self.load_registered_servers()    
       self.load_clients()
       self.clients = {}
       self.servers = {}
     
       
       #initialize phase
    def load_port_info(self):
       try:
           with open("port.info", "r") as file:
               port = int(file.read().strip())
               return port
       except FileNotFoundError:
           print("Warning: port.info file not found. Using default port 1256.")
           return 1256

    def load_registered_servers(self):
       # Load registered servers from file (if exists)
       try:
           with open("server.info", "r") as file:
               for line in file:
                   server_data = line.strip().split(":")
                   server_id, server_name, aes_key = server_data
                   self.server[server_id] = {"name": server_name, "aes_key": aes_key}
       except FileNotFoundError:
           pass  # File doesn't exist yet
    
    def save_servers(self):
        # Save server information to file
        with open("server.info", "w") as file:
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
                for line in file:
                    client_data = line.strip().split(":")
                    client_id, name, password_hash, last_seen = client_data
                    self.clients[client_id] = {"name": name, "password_hash": password_hash, "last_seen": last_seen}
        except FileNotFoundError:
            pass  # File doesn't exist yet
        
    def save_clients(self):
        # Save client information to file
        with open("clients.info", "w") as file:
            for client_id, client_info in self.clients.items():
                file.write(f"{client_id}:{client_info['name']}:{client_info['password_hash']}:{client_info['last_seen']}\n")

    def handle_client_requests(self, client_socket):
        #the first function that called, choose which request the client need
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = self.parse_request(request_data)

            # Use a switch case or if-elif statements to handle different request types
            if request.type == RequestAuth.REGISTER_CLIENT:
                response = self.handle_client_connection(request)
            elif request.type == RequestAuth.REGISTER_SERVER:
                response=self.load_registered_servers(request)
            elif request.type == RequestAuth.GET_AES_KEY:
                client_id, encrypted_key, encrypted_ticket = self.handle_request_get_aes_key(request)
                response = (ResponseAuth.AES_KEY_SUCCESS_RESP, {"client_id": client_id, "encrypted_key": encrypted_key, "encrypted_ticket": encrypted_ticket})
            elif request.type == RequestAuth.REQUEST_LIST_OF_MESSAGE_SERVERS:
                response = self.handle_request_server_list_(client_socket)
            
            else:
                response = (ResponseAuth.GENERAL_ERROR,)

    

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()
   
  
        # It's responsible for converting a response object, which contains both a response code and an optional payload,
        # into a string format that can be transmitted over the network to the client.
        return f"{response[0]}:{response[1]}"
   
  
       
        return str(uuid.uuid4())
  
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
                             encrypt_message(aes_key, self.messaging_server_key, ticket_iv),  # Encrypted AES key (32 bytes)
                             expiration_time)  # Expiration time (8 bytes)

        encrypted_ticket = encrypt_message(ticket_data, client_key, get_random_bytes(16))

        return client_id, encrypted_key + encrypted_key_iv, encrypted_ticket

    def handle_request_server_list_(self, sock):
        request = receive_response(sock)  # Receive the request

        # Process the request and generate the server list
        server_list = list(self.servers.values())  # Assuming self.servers is a dictionary of servers
        response_data = self.response_instance.create_server_list_response(server_list)

        send_request(sock, response_data)  # Send the response

    def create_server_list_response(self,server_list):
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
    #consider adding switch case for requests
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_requests, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
   auth_server = AuthenticationServer()
   auth_server.start()
