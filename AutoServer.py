import socket
import threading
import uuid

class AuthenticationServer:
    def __init__(self):
        self.port = self.read_port_info()
        self.clients = {}
        self.devices = {}
        self.load_registered_devices()

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

    def save_registered_devices(self):
        # Save registered devices to file
        with open("server.txt", "w") as file:
            for device_id, device_info in self.devices.items():
                file.write(f"{device_id}:{device_info['name']}:{device_info['aes_key']}\n")

    def handle_client(self, client_socket):
        # Handle client requests in a separate thread
        # TODO: Implement the protocol handling logic
    
      def handle_registration(self, request):
        # Simplified registration logic
        name = request.payload["name"]
        password = request.payload["password"]

        if name not in self.clients:
            client_id = generate_unique_id()
            self.clients[name] = {"client_id": client_id, "password": password}
            response = ResponseMessage(1600, {"client_id": client_id})
        else:
            response = ResponseMessage(1601)

        return response

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Authentication server listening on port {self.port}...")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
        except KeyboardInterrupt:
            print("Authentication server shutting down...")
        finally:
            server_socket.close()
            self.save_registered_devices()

if __name__ == "__main__":
    auth_server = AuthenticationServer()
    auth_server.start()
