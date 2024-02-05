import secrets
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Definitions import Request

#move both function into class so can be access from all entnties
class EncryptionHelper:
# Function for encrypting a message using AES-CBC
    def encrypt_message(message, key, iv):
        padded_message = pad(message.encode(), AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        return encrypted_message

    # Function for decrypting a message encrypted with AES-CBC
    @staticmethod
    def decrypt_message(encrypted_message, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(encrypted_message)
        unpadded_message = unpad(decrypted_message, AES.block_size)
        return unpadded_message.decode()

    # Function for sending a request to the server
    @staticmethod
    def send_request(sock, request):
        sock.send(request.encode())

    # Function for receiving a response from the server
    @staticmethod
    def receive_response(sock):
        response = sock.recv(1024).decode()
        return response

    # Function to handle a server-side error
    @staticmethod
    def handle_server_error():
        print("server responded with an error")
    @staticmethod
    def get_random_bytes(length):
        if length not in [16, 32]:
            raise ValueError("Invalid length. Please specify 16 or 32 bytes.")
        return secrets.token_bytes(length)
    
    @staticmethod
    def get_auth_port_number():
        try:
            with open("port.info", 'r') as file:
                auth_port_num = file.readline().strip()
            return int(auth_port_num)
        except (FileNotFoundError, ValueError):
            # Return 1236 if file doesn't exist or if the content is not an integer
            return 1236
    @staticmethod
    def parse_request(request_data):
        parts = request_data.strip().split(":")
        
        # Make sure there are at least two parts before trying to return them
        if len(parts) >= 2:
            request_type = int(parts[0])
            payload = ":".join(parts[1:])
            return request_type, payload
        else:
            # Handle the case where there are not enough parts
            raise ValueError("Invalid request_data format")
    
    @staticmethod
    def serialize_response(self, response):
            # It's responsible for converting a response object, which contains both a response code and an optional payload,
            # into a string format that can be transmitted over the network to the client.
            return f"{response[0]}:{response[1]}"
    
   
    """
    usage example on how to encrypt_message and decrypt_message
    helper = EncryptionHelper()
    message = "Hello, world!"
    key = b"your_secure_key"  # Replace with a strong, unique key
    iv = helper.get_random_bytes(AES.block_size)  # Generate a random initialization vector
"""
