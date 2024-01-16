import socket
import threading
import uuid
from Definitions import *

class AuthenticationServer:
   def __init__(self):
       self.port = self.read_port_info()
       self.load_clients()
       self.clients = {}
       self.devices = {}
       self.tgt_cache = {}
       self.clients_file = "clients.txt"
       self.load_registered_devices()    
       
   def generate_tgt(self):
        return str(uuid.uuid4())  # Generate 16-byte random string as TGT

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
           with open("server.txt", "r") as file:
               for line in file:
                   device_data = line.strip().split(":")
                   device_id, device_name, aes_key = device_data
                   self.devices[device_id] = {"name": device_name, "aes_key": aes_key}
       except FileNotFoundError:
           pass  # File doesn't exist yet
    
   def save_clients(self):
        # Save client information to file
        with open(self.clients_file, "w") as file:
            for client_id, client_info in self.clients.items():
                file.write(f"{client_id}:{client_info['name']}:{client_info['password_hash']}:{client_info['last_seen']}\n")

   def load_clients(self):
        # Load client information from file (if exists)
        try:
            with open(self.clients_file, "r") as file:
                for line in file:
                    client_data = line.strip().split(":")
                    client_id, name, password_hash, last_seen = client_data
                    self.clients[client_id] = {"name": name, "password_hash": password_hash, "last_seen": last_seen}
        except FileNotFoundError:
            pass  # File doesn't exist yet
   
   def handle_client(self, client_socket):
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = parse_request(request_data)

            # Handle different types of requests
            if request.type == RequestAuth.REGISTER:
                response = self.handle_register(request)
            elif request.type == RequestAuth.GET_TGT:
                response = self.handle_get_tgt(request)
            else:
                response = (ResponseAuth.UNKNOWN_REQUEST_RESP,)

            # Send the response to the client
            client_socket.sendall(serialize_response(response))

        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            # Close the client socket
            client_socket.close()
   
   
   
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
        name = request.payload["name"]
        password = request.payload["password"]

        if name not in self.clients:
            client_id = self.generate_unique_id()
            self.clients[name] = {"client_id": client_id, "password": password}

            tgt = self.generate_tgt()  
            self.tgt_cache[tgt] = client_id

            response = (ResponseAuth.REGISTER_SUCCESS_RESP, {"client_id": client_id, "tgt": tgt})
        else:
            response = (ResponseAuth.REGISTER_FAILURE_RESP)

        return response
   def handle_get_tgt(self, request):
        client_id = request.payload["client_id"]
        if client_id in self.tgt_cache:
            tgt = self.tgt_cache[client_id]
            response = (ResponseAuth.GET_TGT_SUCCESS_RESP, {"tgt": tgt})
        else:
            tgt = self.generate_tgt()
            self.tgt_cache[client_id] = tgt
            response = (ResponseAuth.GET_TGT_SUCCESS_RESP, {"tgt": tgt})

        return response
  
   def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Authentication server listening on port {self.port}...")

        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
   auth_server = AuthenticationServer()
   auth_server.start()
