import secrets
import socket
import time
import ClientComm
from Definitions import *
from basicFunctions import *


class Client:
    def __init__(self, auth_server_ip, auth_server_port):
        self.client_id = None
        self.encryption_helper = EncryptionHelper()
        self.clientName, self.client_id = self.read_client_info()
        self.auth_server_ip = auth_server_ip
        self.auth_server_port = auth_server_port
        self.message_server_ip = ""
        self.message_server_port = ""
        server_list = {}
        self.ticket = None

        # Create persistent connections
        self.auth_sock = " "
        self.message_sock = ""

    def read_client_info(self):
        try:
            with open("me.info", "r") as file:
                lines = file.readlines()
                if len(lines) < 2:
                    raise ValueError("Invalid format in me.info file")

                client_name = lines[0].strip()
                client_ID = lines[1].strip()
                return client_ID, client_name
        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def register_with_auth_server(self, auth_sock):
        while True:
            username = input("Enter username: ")
            password = input("Enter password: ")

            # Add null terminator if missing
            if username[-1] != '\0':
                username += '\0'
            if password[-1] != '\0':
                password += '\0'

            # Validate username
            if len(username) < 5 or len(username) > 30:
                print("Error: Username must be between 5 and 30 characters long.")
                continue

            # Validate password
            if len(password) < 8 or len(password) > 30:
                print("Error: Password must be between 8 and 30 characters long.")
                continue

            # Continue if validation passes
            break

        request_data = r.MyRequest.register_client(username, password)
        print(request_data)
        auth_sock.send(request_data)
        response = auth_sock.recv(1024)
        header, payload = self.encryption_helper.unpack_auth(HeadersFormat.AUTH_RESP_HEADER.value, response)
        if header[1] != 1600:
            print("Error: Registration failed.")
            return

        # Save the client ID
        self.client_id = payload
        print(self.client_id)
        print(Color.GREEN.value + "Registration successful." + Color.RESET.value)

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
                'server_info': (server_name.decode().rstrip('\x00'), f"192.168.1.{server_id}")
                # Replace with actual IP logic
            })

        return server_list

    def request_server_list(self, auth_sock):
        request_data = r.MyRequest.request_message_server_list(self.client_id)
        auth_sock.send(request_data)
        print(request_data)
        response = auth_sock.recv(1024)
        print(response)
        server_list = self.parse_server_list(response)

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
        # Requests an AES key from the authentication server for a specific server.

        nonce_length = 8
        nonce = secrets.token_bytes(nonce_length)
        request_data = r.MyRequest.request_aes_key(self, client_ID, server_ID, nonce)

        # Send the request to the authentication server

        self.auth_sock.send(request_data)
        response = self.auth_sock.recv(1024)

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
        authenticator = self.encryption_helper.encrypt_message(authenticator_data, self.messaging_server_key,
                                                               get_random_bytes(16))

        # Create the request data
        request_data = authenticator + ticket

        return request_data

    def messaging_the_message_server(self, aes_key):

        message = input("Enter your message: ")

        # Generate a random 16-byte IV (initialization vector)
        iv = secrets.token_bytes(16)

        # Encrypt the message using AES-CBC mode
        encrypted_message = self.encryption_helper.encrypt_message(message.encode(), aes_key, iv)

        # Prepend the 4-byte message size (assuming little-endian)
        request_data = len(encrypted_message).to_bytes(4, "little") + iv + encrypted_message

        # Send the request data to the message server
        self.auth_sock.send(request_data)

        encrypted_message = self.encryption_helper.encrypt_message(message, aes_key,
                                                                   iv)  # Assuming `encrypt_message` is defined
        request_data = self.encryption_helper.request_aes_key(self, len(encrypted_message), iv, encrypted_message)

    def main(client, r):
        # AuthServer Part
        auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_sock.connect((client.auth_server_ip, client.auth_server_port))
        client.register_with_auth_server(auth_sock)
        server_list = client.request_server_list(auth_sock)
        selected_server_id = client.prompt_user_for_server_selection(server_list)
        client.request_aes_key(client.client_id, server_list[selected_server_id]['server_id'])
        auth_sock.close()

        # MessageServer Part
        message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        message_sock.connect((client.message_server_ip, client.message_server_port))
        client.sending_aes_key_to_message_server(client.client_id, server_list[selected_server_id]['server_id'])
        client.messaging_the_message_server(client.aes_key)
        message_sock.close()


if __name__ == "__main__":
    client = Client("127.0.0.1", 1234)
    r = ClientComm.SpecificRequest(client.auth_server_ip, client.auth_server_port)
    client.main(r)
