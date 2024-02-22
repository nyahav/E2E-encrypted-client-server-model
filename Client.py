import hashlib
import json
import os
import secrets
import socket
import time
import re

import ClientComm
from Definitions import *
from basicFunctions import *


class Client:
    def __init__(self, auth_server_ip, auth_server_port):
        self.aes_key = None
        self.client_id = None
        self.hashPassword = None
        self.encryption_helper = EncryptionHelper()
        self.clientName, self.client_id = self.read_client_info()
        self.auth_server_ip = auth_server_ip
        self.auth_server_port = auth_server_port
        self.message_server_ip = ""
        self.message_server_port = ""
        self.server_list = []
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
            self.hashPassword = hashlib.sha256(password.encode('utf-8')).hexdigest()

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
        auth_sock.send(request_data)
        response = auth_sock.recv(1024)
        header, payload = self.encryption_helper.unpack_auth(HeadersFormat.AUTH_RESP_HEADER.value, response)
        if header[1] != 1600:
            print("Error: Registration failed.")
            return

        # Save the client ID
        self.client_id = payload
        print(Color.GREEN.value + "Registration successful." + Color.RESET.value)

    def parse_server_list(self, payload):
        server_list = []
        index = 0

        # Unpack the payload header (version, code, payload size)
        header_format = "<B2sI"
        header_size = struct.calcsize(header_format)
        version_byte, code_bytes, payload_size = struct.unpack(header_format, payload[index:index + header_size])
        code = int.from_bytes(code_bytes, byteorder='little')
        if code != ResponseAuth.RESPONSE_MESSAGE_SERVERS_LIST:
            raise ValueError("Invalid response code: {}".format(code))

        # Move the index to the beginning of the server information
        index += header_size
        counter = 1  # Initialize the counter

        # Iterate over the payload to extract server information
        while index < len(payload):
            # Find the position of the next '}{'
            end_pos = payload.find(b'}{', index)
            if end_pos == -1:
                # This is the last server info object
                server_info_data = payload[index:]
            else:
                # Extract the server info data
                server_info_data = payload[index:end_pos + 1]

            # Use regular expression to find complete JSON objects
            server_info_list = re.findall(br'{.*?}', server_info_data)

            for server_info_str in server_info_list:
                # Load JSON data
                server_info = json.loads(server_info_str.decode('utf-8'))

                # Extract server ID, name, IP, and port
                server_id = server_info.get('server_id')
                server_name = server_info.get('server_name')
                server_ip = server_info.get('ip')
                server_port = server_info.get('port')

                if server_id is not None and server_name is not None:
                    # Use server_id as a key and create a tuple with server name and IP
                    server_list.append({
                        'serial_number': counter,
                        'server_name': server_name,
                        'server_id': server_id,
                        'server_ip': server_ip,
                        'server_port': server_port
                    })
                    counter += 1

            # Move the index to the next server information
            index += len(server_info_data)

        return server_list

    def request_server_list(self, auth_sock):
        request_data = r.MyRequest.request_message_server_list(self.client_id)
        auth_sock.send(request_data)

        # Initialize an empty buffer to store the response
        buffer = b''
        # Define an initial buffer size
        buffer_size = 1024
        # Define the maximum buffer size (1 MB)
        max_buffer_size = 1024 * 1024  # 1 MB
        # Receive the initial chunk of the response
        chunk = auth_sock.recv(buffer_size)
        buffer += chunk

        # Check if the received chunk is smaller than the buffer size
        while len(chunk) == buffer_size:
            # Double the buffer size for the next receive operation
            buffer_size *= 2
            if buffer_size > max_buffer_size:
                raise RuntimeError("Response exceeds maximum buffer size (1 MB)")
            # Receive the next chunk of the response
            chunk = auth_sock.recv(buffer_size)
            buffer += chunk

        # Once the entire response is received, parse the server list
        server_list = self.parse_server_list(buffer)
        return server_list

    def prompt_user_for_server_selection(self):
        """Prompts the user to select a server from the provided list and validates their choice."""

        while True:
            print(Color.GREEN.value + "Available servers:" + Color.RESET.value)
            for i, server in enumerate(self.server_list):
                print(f"{i + 1}. {server['server_name']} ({server['server_id']})")

            try:
                user_selection = int(input(
                    Color.GREEN.value + "Enter the number of the server you want to connect to: " + Color.RESET.value)) - 1

                if 0 <= user_selection < len(self.server_list):
                    selected_server = self.server_list[user_selection]
                    selected_server_id = selected_server['server_id']
                    self.message_server_ip = selected_server['server_ip']
                    self.message_server_port = selected_server['server_port']
                    return selected_server_id
                else:
                    print("Invalid selection. Please enter a valid server number.")
            except ValueError:
                print("Invalid input. Please enter a valid integer.")

    def request_aes_key(self, auth_sock, client_id, server_id):
        # Requests an AES key from the authentication server for a specific server.
        nonce_length = 8
        nonce = secrets.token_bytes(nonce_length)
        request_data = r.MyRequest.request_aes_key_from_auth(self, client_id, server_id, nonce)
        auth_sock.send(request_data)
        print(request_data)
        response = auth_sock.recv(1024)
        ticket_data_length, session_key_length = struct.unpack("<II", response[:8])

        # Extract ticket_data and encrypted_key
        ticket_data = response[8:8 + ticket_data_length]
        session_key_and_iv = response[8 + ticket_data_length:]

        # Extract the encrypted key and client_iv
        client_iv_size = 16  # Assuming client_iv is 16 bytes long
        session_key_length = len(session_key_and_iv) - client_iv_size
        session_key = session_key_and_iv[:session_key_length]
        client_iv = session_key_and_iv[session_key_length:]
        # Decrypt the encrypted key
        session_key_after_decryption = self.encryption_helper.decrypt_message(session_key,
                                                                              self.hashPassword,
                                                                              client_iv)

        # Split the decrypted key into messageserver_key and nonce
        messageserver_key = session_key_after_decryption[:-nonce_length]
        nonce_sent_back = session_key_after_decryption[-nonce_length:]
        if nonce_sent_back != nonce:
            print("Error: Nonce mismatch")
        self.aes_key = messageserver_key  # Assuming payload holds the AES key

        return ticket_data

    def sending_aes_key_to_message_server(self, message_sock, client_id, server_id, ticket):
        # Sends an authenticator and ticket to the messaging server.

        time_stamp = time.time()
        iv = os.urandom(16)
        # Pack the authenticator data using struct
        authenticator_data = struct.pack("<B16s16sQ",
                                         VERSION,  # Version (1 byte)
                                         client_id,  # Client ID (16 bytes)
                                         server_id.encode(),  # Server ID (16 bytes)
                                         int(time_stamp))  # Creation time (8 bytes)
        print("authenticator_data " + str(authenticator_data))
        authenticator = self.encryption_helper.encrypt_message(authenticator_data, self.aes_key, iv)
        print("authenticator " + str(authenticator))
        # Calculate lengths of authenticator and ticket
        authenticator_length = len(authenticator)
        ticket_length = len(ticket)
        # Pack lengths and data into request
        request_data = struct.pack("<II", authenticator_length, ticket_length) + iv + authenticator + ticket
        request_data_with_header = r.MyRequest.sending_aes_key_to_message_server(self.client_id, request_data)
        message_sock.send(request_data_with_header)
        response = message_sock.recv(1024)
        # need to parse response to get back code
        if response != ResponseMessage.APPROVE_SYMETRIC_KEY:
            print("error")

    def messaging_the_message_server(self, auth_sock):

        message = input("Enter your message: ")
        # Generate a random 16-byte IV (initialization vector)
        iv = os.urandom(16)
        # Encrypt the message using AES-CBC mode
        encrypted_message = self.encryption_helper.encrypt_message(message.encode(), self.aes_key, iv)
        # Prepend the 4-byte message size (assuming little-endian)
        request_data = r.MyRequest.sending_message_to_message_server(self.client_id,
                                                                     len(encrypted_message).to_bytes(4, "little"),
                                                                     iv,
                                                                     encrypted_message)
        # Send the request data to the message server
        auth_sock.send(request_data)
        response = auth_sock.recv(1024)
        # need to parse response to get back code
        if response != ResponseMessage.APPROVE_MESSAGE_RECIVED:
            print("error")

    def main(client, r):
        # AuthServer Part
        auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_sock.connect((client.auth_server_ip, client.auth_server_port))
        client.register_with_auth_server(auth_sock)
        client.server_list = client.request_server_list(auth_sock)
        selected_server_id = client.prompt_user_for_server_selection()
        ticket = client.request_aes_key(auth_sock, client.client_id, selected_server_id)
        auth_sock.close()

        # MessageServer Part
        message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        message_sock.connect((client.message_server_ip, int(client.message_server_port)))
        client.sending_aes_key_to_message_server(message_sock, client.client_id, selected_server_id, ticket)
        client.messaging_the_message_server(message_sock)
        message_sock.close()


if __name__ == "__main__":
    client = Client("127.0.0.1", 1234)
    r = ClientComm.SpecificRequest(client.auth_server_ip, client.auth_server_port)
    client.main(r)
