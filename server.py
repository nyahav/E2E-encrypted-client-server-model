import socket
import threading
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class MessageServer:
    def __init__(self):
        self.port = self.read_port_info()
        self.server_info = self.read_server_info()
        self.clients = {}

    def read_port_info(self):
        try:
            with open("port.info", "r") as file:
                port = int(file.read().strip())
                return port
        except FileNotFoundError:
            print("Warning: port.info file not found. Using default port 1234.")
            return 1234

    def read_server_info(self):
        try:
            with open("msg.info", "r") as file:
                port = int(file.readline().strip())
                name = file.readline().strip()
                server_id = file.readline().strip()
                symmetric_key = base64.b64decode(file.readline().strip())
                return {"port": port, "name": name, "id": server_id, "symmetric_key": symmetric_key}
        except FileNotFoundError:
            print("Error: msg.info file not found.")
            exit()

    def handle_client(self, client_socket):
        try:
            while True:
                request = client_socket.recv(1024).decode()
                if not request:
                    break

                # TODO: Implement protocol handling logic using PyCryptodome
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", self.port))
        server_socket.listen(5)
        print(f"Message server listening on port {self.port}...")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
        except KeyboardInterrupt:
            print("Message server shutting down...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    msg_server = MessageServer()
    msg_server.start()
