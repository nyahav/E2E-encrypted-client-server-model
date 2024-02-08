import base64
import socket
from Definitions import *
from basicFunctions import *
from MessageComm import SpecificRequest
import secrets


class MessageServer:
    def __init__(self, server_name, port=None, symmetric_key=None, server_id=None):
        self.ip = '127.0.0.1'
        self.port = port
        self.server_name = server_name
        self.symmetric_key = symmetric_key
        self.server_id = server_id
        self.encryption_helper = EncryptionHelper()
        if port is None:
            self.read_server_info()  # Read info from msg(#).info

    def read_server_info(self):
        with open(f"{self.server_name}.info", "r") as f:
            lines = f.readlines()
            if len(lines) >= 4:
                (self.IP, self.port) = lines[0].strip().split(":")
                self.server_id = bytes.fromhex(lines[1].strip())
                self.symmetric_key = base64.b64decode(lines[2].strip())
                self.port = int(self.port)

    def write_server_info(self):
        with open(f"{self.server_name}.info", "w") as file:
            file.write(f"{self.ip}:{self.port}\n")
            print(type(self.server_id))
            file.write(f"{self.server_id.hex}\n")
            file.write(f"{base64.b64encode(self.symmetric_key).decode()}\n")

    def handle_client_request(self, client_socket):
        """Handles incoming client requests."""
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = self.encryption_helper.parse_request(request_data)  # Assuming you have a parsing function

            # Handle different request types
            if request.type == RequestMessage.SEND_SYMETRIC_KEY:
                self.receive_aes_key_from_client(client_socket)
            elif request.type == RequestMessage.SEND_MESSAGE:
                self.receive_message_from_client(client_socket)
            else:
                response = (ResponseMessage.GENERAL_ERROR,)

            client_socket.send(self.encryption_helper.serialize_response(response))
        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()

    # Function to get an AES key from the message server
    def receive_aes_key_from_client(self, sock, authenticator, ticket):
        try:
            aes_key = self.decrypt_ticket_and_aes_key(ticket, authenticator)
            # Receive the encrypted message from the client
            iv, encrypted_message = self.encryption_helper.receive_response(sock).split(' ')
            iv = bytes.fromhex(iv)
            encrypted_message = bytes.fromhex(encrypted_message)

            # Decrypt the message using the decrypted AES key
            decrypted_message = self.encryption_helper.decrypt_message(encrypted_message, aes_key, iv)
            # Send back a success response (code 1604)
            send_request(sock, ResponseMessage.APPROVE_SYMETRIC_KEY)  # Assuming you have a function to send responses
        except:
            print("Error")

    def decrypt_ticket_and_aes_key(ticket, authenticator):
        return 1

    def receive_message_from_client(self, sock):
        try:
            # Receive the size of the incoming message
            message_size = self.encryption_helper.receive_response(sock)[:4]
            message_size = int.from_bytes(message_size, "little")

            # Receive the initialization vector for decryption
            message_iv = self.encryption_helper.receive_response(sock)[:16]

            # Receive the actual message content
            message_content = self.encryption_helper.receive_response(sock)

            # Decrypt the message content using the server's symmetric key
            decrypted_message = self.encryption_helper.decrypt_message(message_content, self.symmetric_key, message_iv)

        except Exception as e:
            print(f"Error receiving message from client: {e}")

        # Process the decrypted message further as needed

    # Define receive_response and decrypt_message methods as needed


def handle_server_registration(server_name, server_port, r):
    eh = EncryptionHelper()
    auth_port_number = eh.get_auth_port_number()
    auth_ip_address = '127.0.0.1'
    auth_aes_key = secrets.token_bytes(32)

    register_data = r.register_server(bytes(16), server_name, auth_aes_key, server_port)

    sign_to_auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_address = (auth_ip_address, auth_port_number)
    sign_to_auth_sock.connect(auth_address)
    sign_to_auth_sock.send(register_data)
    resp_from_auth = sign_to_auth_sock.recv(1024)
    print(f"received from Auth: {resp_from_auth}")
    version, response_type, server_id = SpecificRequest.unpack_register_message_success(resp_from_auth)
    print(f"server_id is: {server_id}")
    new_message_server = MessageServer(server_name, server_port, auth_aes_key, server_id)
    return new_message_server


def main():
    r = SpecificRequest()
    message_server = handle_server_registration("hello", 1145, r)
    message_server.write_server_info()
    # register this message server to the authentication server

    server_address = (message_server.ip, message_server.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        client_sock, client_address = sock.accept()
        try:
            message_server.handle_client_request(client_sock)
        finally:
            client_sock.close()


if __name__ == "__main__":
    main()
