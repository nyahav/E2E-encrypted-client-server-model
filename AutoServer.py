import time
import uuid
import socket
import threading
from Definitions import *
from basicFunctions import encrypt_message,get_random_bytes

class AuthenticationServer:
    def __init__(self):
       self.port = self.read_port_info()
       self.load_registered_devices()    
       self.load_clients()
       self.clients = {}
       self.devices = {}
     
       
       
    def read_port_info(self):
       try:
           with open("port.info", "r") as file:
               port = int(file.read().strip())
               return port
       except FileNotFoundError:
           print("Warning: port.info file not found. Using default port 1256.")
           return 1256

    def load_registered_devices(self):
       # Load registered devices from file (if exists)
       try:
           with open("server.info", "r") as file:
               for line in file:
                   device_data = line.strip().split(":")
                   device_id, device_name, aes_key = device_data
                   self.devices[device_id] = {"name": device_name, "aes_key": aes_key}
       except FileNotFoundError:
           pass  # File doesn't exist yet
    
  
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
        with open(self.clients_file, "w") as file:
            for client_id, client_info in self.clients.items():
                file.write(f"{client_id}:{client_info['name']}:{client_info['password_hash']}:{client_info['last_seen']}\n")

    def handle_client_registration(self, client_socket):
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = self.parse_request(request_data)

            # Handle different types of requests
            if request.type == RequestAuth.REGISTER:
                response = self.handle_register(request)
            else:
                response = (ResponseAuth.GENERAL_ERROR,)

            # Send the response to the client
            client_socket.sendall(self.serialize_response(response))

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            # Close the client socket
            client_socket.close()
   
    def parse_request(self, request_data):
        # Implement the logic to parse the request_data
        parts = request_data.strip().split(":")
        type = int(parts[0])
        payload = parts[1]
        return Request(type, payload)

    def serialize_response(self, response):
        # Implement the logic to serialize the response
        return f"{response[0]}:{response[1]}"
   
    def update_last_seen(self, client_id):
        # Update the last_seen timestamp for a client
        self.clients[client_id]["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
           
    def save_registered_devices(self):
       # Save registered devices to file
       with open("server.txt", "w") as file:
           for device_id, device_info in self.devices.items():
               file.write(f"{device_id}:{device_info['name']}:{device_info['aes_key']}\n")

    def generate_unique_id(self):
       # TODO: Implement the protocol to generate unique id
        return str(uuid.uuid4())

    def handle_register(self, request):
        username = request.payload["username"]
        password = request.payload["password"]

        if username not in self.clients:
            client_id = self.generate_unique_id()
            self.clients[username] = {"client_id": client_id, "password": password}
            
            response = (ResponseAuth.REGISTER_SUCCESS_RESP, {"client_id": client_id})
        else:
            response = (ResponseAuth.REGISTER_FAILURE_RESP)

        return response
    
    
    def handle_get_aes_key(self, request):
        
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
                             24,  # Version (1 byte)
                             client_id.encode(),  # Client ID (16 bytes)
                             server_id.encode(),  # Server ID (16 bytes)
                             creation_time,  # Creation time (8 bytes)
                             ticket_iv,  # Ticket IV (16 bytes)
                             encrypt_message(aes_key, self.messaging_server_key, ticket_iv),  # Encrypted AES key (32 bytes)
                             expiration_time)  # Expiration time (8 bytes)

        encrypted_ticket = encrypt_message(ticket_data, client_key, get_random_bytes(16))

        return client_id, encrypted_key + encrypted_key_iv, encrypted_ticket


    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Authentication server listening on port {self.port}...")

        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_registration, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
   auth_server = AuthenticationServer()
   auth_server.start()
