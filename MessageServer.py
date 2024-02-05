import os
import base64
import socket
from Definitions import *
from basicFunctions import EncryptionHelper
from MessageComm import SpecificRequest


class MessageServer:
    def __init__(self, mServer_num):
        self.encryption_helper = EncryptionHelper()
        self.server_num = mServer_num
        self.read_server_info()  # Read info from msg(#).info

    def read_server_info(self):
        with open(f"msg{self.server_num}.info", "r") as f:
            lines = f.readlines()
            if len(lines) >= 4:
                (self.IP, self.port) = lines[0].strip().split(":")
                self.server_name = lines[1].strip()
                self.server_id = lines[2].strip()
                self.symmetric_key = base64.b64decode(lines[3].strip())
                self.port = int(self.port)

    def write_server_info(self):
        print(self)
        with open(f"msg{self.server_num}.info", "w") as file:
            file.write(f"{self.port}\n")
            file.write(f"{self.server_name}\n")
            file.write(f"{self.server_id}\n")
            file.write(f"{base64.b64encode(self.symmetric_key).decode()}\n")

        #  logic to return the symmetric key for a specific server
        client_id = Request.payload["client_id"]
        response = (ResponseMessage.RESPONSE_SYMETRIC_REQ, {"aes_key": self.aes_key, "client_id": client_id})
        return response

# Function to perform a registration request to the authentication server
#read auth server information from port.info
def register_to_auth_server(sock, username):
    request = f"REGISTER {username}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Registration successful")
        
#Function to decide which request the client sent and which function to call       
def handle_client_request(self, client_socket):
    """Handles incoming client requests."""

            client_socket.send(serialize_response(response))

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def user_register_to_auth_server(self, sock, username):
        request = f"REGISTER {username}"
        send_request(sock, request)
        response = receive_response(sock)
        if response == "ERROR":
            handle_server_error()
        else:
            print("Registration successful")

    def receive_aes_key_from_client(self, sock, authenticator, ticket):
        try:
            aes_key = decrypt_ticket_and_aes_key(ticket, authenticator)
            # Receive the encrypted message from the client
            iv, encrypted_message = receive_response(sock).split(' ')
            iv = bytes.fromhex(iv)
            encrypted_message = bytes.fromhex(encrypted_message)

            # Decrypt the message using the decrypted AES key
            decrypted_message = decrypt_message(encrypted_message, aes_key, iv)

            # Send back a success response (code 1604)
            send_request(sock, ResponseMessage.APPROVE_SYMETRIC_KEY)

            print(f"Received message: {decrypted_message.decode()}")
        except Exception as e:
            # Send back an error response (code 1609)
            send_request(sock, ResponseMessage.GENERAL_ERROR)
            print(f"Error handling message: {e}")

    def receive_message_from_client(self, sock):
        try:
            message_size = receive_response(sock)[:4]
            message_size = int.from_bytes(message_size, "little")
            message_iv = receive_response(sock)[:16]
            message_content = receive_response(sock)

            # Decrypt the message content using the message server's symmetric key
            aes_key = self.aes_key
            decrypted_message = decrypt_message(message_content, aes_key, message_iv)

            # Send back an acknowledgement (code 1605)
            send_request(sock, ResponseMessage.APPROVE_MESSAGE_RECIVED)

            print(f"Received message: {decrypted_message.decode()}")
        except Exception as e:
            send_request(sock, ResponseMessage.GENERAL_ERROR)
            print(f"Error handling message: {e}")

# Function to get an AES key from the client
def receive_aes_key_from_client(self,sock,authenticator, ticket):
    try:
        aes_key = decrypt_ticket_and_aes_key(ticket, authenticator)  
        # Receive the encrypted message from the client
        iv, encrypted_message = receive_response(sock).split(' ')
        iv = bytes.fromhex(iv)
        encrypted_message = bytes.fromhex(encrypted_message)

        # Decrypt the message using the decrypted AES key
        decrypted_message = decrypt_message(encrypted_message, aes_key, iv)

        # Send back a success response (code 1604)
        send_request(sock, ResponseMessage.APPROVE_SYMETRIC_KEY)  # Assuming you have a function to send responses

        print(f"Received message: {decrypted_message.decode()}")
    except Exception as e:
        # Send back an error response (code 1609)
        send_request(sock, ResponseMessage.GENERAL_ERROR)
        print(f"Error handling message: {e}")

# Function to receive a message from the client
def receive_message_from_client(self,sock):
    try:
        message_size = receive_response(sock)[:4]
        message_size = int.from_bytes(message_size, "little")
        message_iv = receive_response(sock)[:16]
        message_content = receive_response(sock)

        # Decrypt the message content using the message server's symmetric key
        aes_key = message_server.aes_key
        decrypted_message = decrypt_message(message_content, aes_key, message_iv)

        # Send back an acknowledgement (code 1605)
        send_request(sock, ResponseMessage.APPROVE_MESSAGE_RECIVED)

        print(f"Received message: {decrypted_message.decode()}")
    except Exception as e:
          send_request(sock, ResponseMessage.GENERAL_ERROR)  
          print(f"Error handling message: {e}")
    

    def handle_client_request(self, client_socket):
        """Handles incoming client requests."""
        try:
            # Receive the request from the client
            request_data = client_socket.recv(1024).decode("utf-8")
            request = self.encryption_helper.parse_request(request_data)

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

    def receive_aes_key_from_client(self, sock, authenticator, ticket):
        try:
            aes_key = decrypt_ticket_and_aes_key(ticket, authenticator)
            # Receive the encrypted message from the client
            iv, encrypted_message = receive_response(sock).split(' ')
            iv = bytes.fromhex(iv)
            encrypted_message = bytes.fromhex(encrypted_message)

            # Decrypt the message using the decrypted AES key
            decrypted_message = decrypt_message(encrypted_message, aes_key, iv)
            # Send back a success response (code 1604)
            send_request(sock, ResponseMessage.APPROVE_SYMETRIC_KEY)  # Assuming you have a function to send responses
        except:
            print("Error")

    def decrypt_ticket_and_aes_key(self, ticket, authenticator):
        pass

    def receive_message_from_client(self, sock):
        try:
            # Receive the size of the incoming message
            message_size = self.receive_response(sock)[:4]
            message_size = int.from_bytes(message_size, "little")

            # Receive the initialization vector for decryption
            message_iv = self.receive_response(sock)[:16]

            # Receive the actual message content
            message_content = self.receive_response(sock)

            # Decrypt the message content using the server's symmetric key
            decrypted_message = self.decrypt_message(
                message_content, self.symmetric_key, message_iv)

        except Exception as e:
            print(f"Error receiving message from client: {e}")

        # Process the decrypted message further as needed

    # Define receive_response and decrypt_message methods as needed


def main():
    r = SpecificRequest()
    mServer_num = 1  # Define your server number or ID here, different for every Thread
    message_server = MessageServer(mServer_num)

    # Register this message server to the authentication server
    auth_port_number = message_server.encryption_helper.get_auth_port_number()
    register_data = r.register_server(
        message_server.server_id, message_server.server_name, message_server.symmetric_key)
    
    print("MessageServer is running on port: {server_address}")
    print(register_data)
    sign_to_auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_address = ('127.0.0.1', auth_port_number)
    sign_to_auth_sock.connect(auth_address)
    sign_to_auth_sock.send(register_data)

    server_address = (message_server.IP, message_server.port)
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
