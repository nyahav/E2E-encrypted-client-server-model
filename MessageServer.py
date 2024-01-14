import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def __init__(self, server_id, aes_key):
        self.server_id = server_id
        self.aes_key = aes_key

def handle_get_server_list(self, request):
        #  logic to return a list of servers
        server_list = [{"server_id": "server1", "server_name": "Message Server 1"}]
        response = ResponseMessage(1602, {"servers": server_list})
        return response

def handle_get_aes_key(self, request):
        #  logic to return the symmetric key for a specific server
        client_id = request.payload["client_id"]
        response = ResponseMessage(0416, {"aes_key": self.aes_key, "client_id": client_id})
        return response

# Function for encrypting a message using AES-CBC
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

# Function for decrypting a message encrypted with AES-CBC
def decrypt_message(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.rstrip(b'\0')  # Remove padding

# Function for sending a request to the server
def send_request(sock, request):
    sock.send(request.encode())

# Function for receiving a response from the server
def receive_response(sock):
    response = sock.recv(1024).decode()
    return response

# Function to handle a server-side error
def handle_server_error():
    print("server responded with an error")

# Function to perform a registration request to the authentication server
def register_to_auth_server(sock, username):
    request = f"REGISTER {username}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Registration successful")

# Function to send a request for a list of message servers to the authentication server
def get_message_servers_list(sock):
    request = "GET_SERVERS_LIST"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Message servers list:")
        print(response)

# Function to get an AES key from the message server
def get_aes_key_from_message_server(sock, server_id):
    request = f"GET_AES_KEY {server_id}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
        return None
    else:
        print(f"AES key received from message server {server_id}")
        return response.encode()

# Function to send a message to the message server
def send_message_to_server(sock, message, aes_key, ticket):
    iv = get_random_bytes(16)
    encrypted_message = encrypt_message(message.encode(), aes_key, iv)
    request = f"SEND_MESSAGE {iv.hex()} {encrypted_message.hex()} {ticket}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Message sent successfully")

# Function to receive a message from the message server
def receive_message_from_server(sock, aes_key, ticket):
    request = f"RECEIVE_MESSAGE {ticket}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        iv, encrypted_message = response.split(' ')
        iv = bytes.fromhex(iv)
        encrypted_message = bytes.fromhex(encrypted_message)
        decrypted_message = decrypt_message(encrypted_message, aes_key, iv)
        print(f"Received message: {decrypted_message.decode()}")

# Main function to initiate communication with servers
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

    sock.close()

if __name__ == "__main__":
    main()