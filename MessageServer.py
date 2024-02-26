import argparse
import base64
import socket
import secrets
import subprocess
import struct
import time
import uuid
from MessageComm import SpecificRequest
from Definitions import HeadersFormat, Header, RequestMessage, ResponseMessage
from basicFunctions import EncryptionHelper


class MessageServer:
    def __init__(self, server_name=None, port=None, symmetric_key=None, server_id_bin=None):
        if server_name is None:
            server_name = f"server_{uuid.uuid4().hex}"  # Generate a unique server name
        if port is None:
            port = self.find_available_port()  # Find an available port dynamically
        self.ip = '127.0.0.1'
        self.port = port
        self.server_name = server_name
        self.symmetric_key = symmetric_key
        self.server_id = uuid.UUID(bytes=server_id_bin)  # ascii form
        print("Server id: ", self.server_id)
        self.encryption_helper = EncryptionHelper()

    @staticmethod
    def find_available_port():
        """Find an available port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))  # Bind to any available port
        port = sock.getsockname()[1]  # Get the port
        sock.close()
        return port

    def read_server_info(self):
        with open(f"{self.server_name}.info", "r") as f:
            lines = f.readlines()
            if len(lines) >= 4:
                (self.ip, self.port) = lines[0].strip().split(":")  # Update IP and port
                self.server_id = uuid.UUID(lines[1].strip())
                self.symmetric_key = base64.b64decode(lines[2].strip())
                self.port = int(self.port)

    def write_server_info(self):
        with open(f"{self.server_name}.info", "w") as file:
            file.write(f"{self.ip}:{self.port}\n")
            file.write(f"{self.server_id.hex}\n")
            file.write(f"{base64.b64encode(self.symmetric_key).decode()}\n")

    def handle_client_request(self, r, client_socket):
        """Handles incoming client requests."""
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024)
            header, payload = self.encryption_helper.unpack(HeadersFormat.CLIENT_FORMAT.value, request_data)
            request_type = header[Header.CODE.value]
            request_client_id_bin = header[Header.CLIENT_ID.value]
            print("request_type " + str(request_type))
            # Handle different request types
            if request_type == RequestMessage.SEND_SYMETRIC_KEY:
                response = self.receive_aes_key_from_client(r, payload)
            elif request_type == RequestMessage.SEND_MESSAGE:
                response = self.receive_message_from_client(r, payload)
            else:
                response = (ResponseMessage.GENERAL_ERROR,)

            client_socket.send(response)
        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()

    # Function to get an AES key from the message server
    def receive_aes_key_from_client(self, r, request):
        try:
            auth_length, ticket_length = struct.unpack("<II", request[:8])
            iv = request[8:24]
            authenticator_end = 24 + auth_length
            authenticator = request[24:authenticator_end]
            ticket = request[authenticator_end:authenticator_end + ticket_length]

            try:
                total_ticket_length = ticket_length
                # Lengths of known-size fields
                known_fields_length = struct.calcsize("<B16s16sQ16s")

                # Calculate the length of the encrypted message
                encrypted_message_length = total_ticket_length - known_fields_length

                # Extract known-size fields from the ticket
                versionT, client_idT, server_id_binT, creation_timeT, ticket_iv = struct.unpack("<B16s16sQ16s", ticket[
                                                                                                                :known_fields_length])
                # Extract encrypted message
                encrypted_data = ticket[known_fields_length:]
                print("messageServer_key " + str(self.symmetric_key))
                # Decrypt the encrypted message using the ticket IV and symmetric key
                decrypted_data = self.encryption_helper.decrypt_message(encrypted_data, self.symmetric_key, ticket_iv)

                # Extract expiration time and client message session key from decrypted data
                expiration_time_length = 8
                client_message_session_key_length = 32

                # Extract client message session key
                client_message_session_key = decrypted_data[:client_message_session_key_length]

                # Extract expiration time
                expiration_time_start_index = client_message_session_key_length  # Start index of expiration time
                expiration_time = decrypted_data[
                                  expiration_time_start_index:expiration_time_start_index + expiration_time_length]

                decrypted_auth = self.encryption_helper.decrypt_message(authenticator, client_message_session_key, iv)
                decrypted_auth_unpack = struct.unpack("<B16s16sQ", decrypted_auth)
                versionA = decrypted_auth_unpack[0]
                client_idA = decrypted_auth_unpack[1]
                server_idA = decrypted_auth_unpack[2]
                creationismA = decrypted_auth_unpack[3]

                if (versionA != versionT or
                        client_idA != client_idT or
                        server_idA != server_id_binT):
                    print("Mismatch between authenticator and ticket")
                    return ResponseMessage.GENERAL_ERROR
                    # Check if expiration time is valid
                expiration_time_int = int.from_bytes(expiration_time, byteorder='little')
                if expiration_time_int <= creation_timeT or expiration_time_int > creation_timeT + 60:
                    print("Invalid expiration time")
                    return r.general_error(client_idA)
            except ValueError as e:
                print("Decryption error:", e)
                return r.general_error(client_idA)

            # Send back a success response (code 1604)
            return r.approve_aes_receive(client_idA)

        except Exception as ex:
            print("Exception:", ex)
            return r.general_error(client_idA)

    def receive_message_from_client(self, request):
        try:
            # Define the format string to unpack the data
            format_string = '<I16s'
            message_size, message_iv = struct.unpack(format_string, request[:20])
            message_content = request[20:]
            decrypted_message = self.encryption_helper.decrypt_message(message_content, self.symmetric_key, message_iv)
            print(decrypted_message)
            return ResponseMessage.APPROVE_MESSAGE_RECIVED
        except Exception as e:
            print(f"Error receiving message from client: {e}")
            return ResponseMessage.GENERAL_ERROR
        # Process the decrypted message further as needed

    # Define receive_response and decrypt_message methods as needed

def handle_server_registration(server_name, server_ip, server_port, r):
    # Check if the server already exists
    with open("srvname.info", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 3:
                name, ip_port, _ = parts
                if ip_port == f"{server_ip}:{server_port}":
                    server_info_file = f"{name}.info"
                    with open(server_info_file, "r") as info_file:
                        lines = info_file.readlines()
                        symmetric_key = base64.b64decode(lines[2].strip())
                        server_id_bin = bytes.fromhex(lines[1].strip())
                    return MessageServer(server_name=name, port=server_port, symmetric_key=symmetric_key,
                                         server_id_bin=server_id_bin)

    # If the server doesn't exist, register it with the authentication server
    eh = EncryptionHelper()
    auth_port_number = eh.get_auth_port_number()
    auth_aes_key = secrets.token_bytes(32)
    print("auth_aes_key" + str(auth_aes_key))
    register_data = r.register_server(bytes(16), server_name, auth_aes_key, server_port)

    sign_to_auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_address = (server_ip, auth_port_number)
    sign_to_auth_sock.connect(auth_address)
    sign_to_auth_sock.send(register_data)
    resp_from_auth = sign_to_auth_sock.recv(1024)
    print(f"received from Auth: {resp_from_auth}")
    version, response_type, server_id_bin = SpecificRequest.unpack_register_message_success(resp_from_auth)
    new_message_server = MessageServer(server_name, server_port, auth_aes_key, server_id_bin)
    return new_message_server

def find_available_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))  # Bind to any available port
    port = sock.getsockname()[1]  # Get the port
    sock.close()
    return port


def save_server_name(server_name, server_ip, server_port):
    with open("srvname.info", "a+") as f:
        f.write(f"{server_name}:{server_ip}:{server_port}\n")
        return True



def parse_arguments():
    parser = argparse.ArgumentParser(description="Message Server")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=1145, help="Port to bind to")
    args = parser.parse_args()
    return args.ip, args.port


def main():
    r = SpecificRequest()
    server_name = input("Enter server name: ")
    print("Server name:", server_name)
    server_ip, server_port = parse_arguments()  # Get IP address and port from command-line arguments
    if server_port == 1145:
        server_port = find_available_port()
    print("IP:", server_ip)
    print("Port:", server_port)

    while not save_server_name(server_name, server_ip, server_port):
        server_name = input("Enter another server name: ")

    message_server = handle_server_registration(server_name, server_ip, server_port, r)
    message_server.write_server_info()
    server_address = (message_server.ip, message_server.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        client_sock, client_address = sock.accept()
        try:
            message_server.handle_client_request(r, client_sock)
        finally:
            client_sock.close()


if __name__ == "__main__":
    main()
