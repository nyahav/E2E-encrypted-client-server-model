import base64
import socket
from Definitions import *
from basicFunctions import *
from MessageComm import SpecificRequest
import secrets
import uuid

class MessageServer:
    def __init__(self, server_name, port=None, symmetric_key=None, server_id_bin=None):
        self.ip = '127.0.0.1'
        self.port = port
        self.server_name = server_name
        self.symmetric_key = symmetric_key
        self.server_id = uuid.UUID(bytes=server_id_bin)  # ascii form
        print("Server id: ", self.server_id)
        self.encryption_helper = EncryptionHelper()
        if port is None:
            self.read_server_info()  # Read info from msg(#).info

    def read_server_info(self):
        with open(f"{self.server_name}.info", "r") as f:
            lines = f.readlines()
            if len(lines) >= 4:
                (self.IP, self.port) = lines[0].strip().split(":")
                self.server_id = uuid.UUID(lines[1].strip())
                self.symmetric_key = base64.b64decode(lines[2].strip())
                self.port = int(self.port)

    def write_server_info(self):
        with open(f"{self.server_name}.info", "w") as file:
            file.write(f"{self.ip}:{self.port}\n")
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
                response = self.receive_aes_key_from_client(request)
            elif request.type == RequestMessage.SEND_MESSAGE:
                response = self.receive_message_from_client(request)
            else:
                response = (ResponseMessage.GENERAL_ERROR,)

            client_socket.send(self.encryption_helper.serialize_response(response))
        except Exception as e:
            print(f"Error handling client: {e}")

        finally:
            client_socket.close()

    # Function to get an AES key from the message server
    def receive_aes_key_from_client(self, request):
        try:
            iv, authenticator, ticket = struct.unpack('<16s8s', request)
            #authernticator decrption
            try:
                versionA, client_idA, server_idA, creationtimeA = self.encryption_helper.decrypt_message(authenticator,
                                                                                                     self.symmetric_key,
                                                                                                     iv)
            except ValueError as e:
                print("Decryption error:", e)
                return ResponseMessage.GENERAL_ERROR
            # ticket decrption
            try:
                unpacked_data = struct.unpack("<B16s16sQ16s32s", ticket)

                # Extract individual fields
                versionT = unpacked_data[0]
                client_idT = unpacked_data[1]
                server_id_binT = unpacked_data[2]
                creation_timeT = unpacked_data[3]
                ticket_iv = unpacked_data[4]
                encrpyted_data = unpacked_data[5]
                decrypted_data = self.encryption_helper.decrypt_message(encrpyted_data,self.symmetric_key,iv)

                # Calculate the size of expiration_time
                expiration_time_size = 8  # Assuming 8 bytes for expiration_time

                # Calculate the size of ticket_aes_key
                ticket_aes_key_size = len(decrypted_data) - expiration_time_size

                # Extract ticket_aes_key and expiration_time from decrypted_data
                ticket_aes_key = decrypted_data[:ticket_aes_key_size]
                expiration_time_bytes = decrypted_data[ticket_aes_key_size:]
                # Convert expiration_time_bytes to integer
                expiration_time = struct.unpack('<Q', expiration_time_bytes)[0]
            except ValueError as e:
                    print("Decryption error:", e)
                return ResponseMessage.GENERAL_ERROR



            # Send back a success response (code 1604)
            return ResponseMessage.APPROVE_SYMETRIC_KEY
        except Exception as ex:
            print("Exception:", ex)
            return ResponseMessage.GENERAL_ERROR


    def receive_message_from_client(self, request):
        try:
            # Define the format string to unpack the data
            format_string = '<I16s'
            message_size, message_iv = struct.unpack(format_string, request[:20])
            message_content =request[20:]
            decrypted_message = self.encryption_helper.decrypt_message(message_content, self.symmetric_key, message_iv)
            print(decrypted_message)
            return ResponseMessage.APPROVE_MESSAGE_RECIVED
        except Exception as e:
            print(f"Error receiving message from client: {e}")
            return ResponseMessage.GENERAL_ERROR
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
    version, response_type, server_id_bin = SpecificRequest.unpack_register_message_success(resp_from_auth)
    new_message_server = MessageServer(server_name, server_port, auth_aes_key, server_id_bin)
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