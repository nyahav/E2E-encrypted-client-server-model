import os
import base64
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Definitions import *
from basicFunctions import *
     
class MessageServer:
    def __init__(self, mServer_num):
            with open("msg1.info", "r") as f:
                lines = f.readlines()
                if len(lines) >= 4:
                    (self.IP,self.port) =lines[0].strip().split(":")
                    self.server_name = lines[1].strip()
                    self.server_id = lines[2].strip()
                    self.symmetric_key = base64.b64decode(lines[3].strip())

                    self.port = int(self.port) 

       
        
def write_server_info(self):
    with open("msg.info", "w") as file:
        file.write(f"{self.port}\n")
        file.write(f"{self.server_name}\n")
        file.write(f"{self.server_ID}\n")
        file.write(f"{base64.b64encode(self.symmetric_key).decode()}\n")
        

        #  logic to return the symmetric key for a specific server
        client_id = request.payload["client_id"]
        response = ResponseAuth(ResponseAuth.RESPONSE_SYMETRIC_REQ, {"aes_key": self.aes_key, "client_id": client_id})
        return response

# Function to perform a registration request to the authentication server
def register_to_auth_server(sock, username):
    request = f"REGISTER {username}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Registration successful")

# Function to get an AES key from the message server
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
        send_response(sock, "1604")  # Assuming you have a function to send responses

        print(f"Received message: {decrypted_message.decode()}")
    except Exception as e:
        # Send back an error response (code 1609)
        send_response(sock, "1609")
        print(f"Error handling message: {e}")

# Function to receive a message from the client
def receive_message_from_client(self):
        message_size = receive_request(sock)[:4]
        message_size = int.from_bytes(message_size, "little")
        message_iv = receive_request(sock)[:16]
        message_content = receive_request(sock)

        # Decrypt the message content using the message server's symmetric key
        aes_key = message_server.aes_key
        decrypted_message = decrypt_message(message_content, aes_key, message_iv)

        # Send back an acknowledgement (code 1605)
        send_request(sock, "1605")

        print(f"Received message: {decrypted_message.decode()}")
        except Exception as e:
        # Send back an error response (code 1609)
          send_request(sock, "1609")
        print(f"Error handling message: {e}")
    


def main():
    server_address = ('127.0.0.1', 1234)  # Replace with the appropriate server details
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)

    username = "user123"
    register_to_auth_server(sock, username)

    get_message_servers_list(sock)

    server_id = "server1"  # Choose a server from the list
    aes_key = get_aes_key_from_message_server(sock, server_id)
    if aes_key:
        ticket = "12345"  # Replace with actual ticket details
        message_to_send = "Hello, server!"
        send_message_to_server(sock, message_to_send, aes_key, ticket)

        receive_message_from_server(sock, aes_key, ticket)

        # Update server information and write it to msg.info
        message_server.server_name = "NewServerName"
        message_server.symmetric_key = get_new_symmetric_key()
        message_server.write_server_info()

    sock.close()

if __name__ == "__main__":
    server_id = "server1"
    aes_key = get_aes_key_from_message_server(sock, server_id)
    message_server = MessageServer(server_id, aes_key)
    message_server.write_server_info()  # Write initial server information to msg.info
    main()