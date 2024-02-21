import binascii
import secrets
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Definitions import Request, HeaderAuth, Header


# move both function into class so can be access from all entities
class EncryptionHelper:
    # Function for encrypting a message using AES-CBC
    @staticmethod
    def encrypt_message(message, key, iv):
        if isinstance(message, bytes):
            padded_message = pad(message, AES.block_size)
        elif isinstance(message, str):
            padded_message = pad(message.encode(), AES.block_size)
        else:
            raise TypeError("Message must be a bytes-like object or a string")

        # Check if the key is a hexadecimal string, if so, convert it to bytes
        if isinstance(key, str):
            key = binascii.unhexlify(key)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        return encrypted_message

    # Function for decrypting a message encrypted with AES-CBC
    @staticmethod
    def decrypt_message(encrypted_message, key, iv):
        try:
            # Check if the key is already in bytes
            if isinstance(key, str):
                key_bytes = bytes.fromhex(key)
            elif isinstance(key, bytes):
                key_bytes = key
            else:
                raise TypeError("Key must be a hex string or bytes")

            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted_message = cipher.decrypt(encrypted_message)
            unpadded_message = unpad(decrypted_message, AES.block_size)
            return unpadded_message
        except ValueError as e:
            # Handle decryption errors (e.g., incorrect key)
            print("Decryption error:", e)
            return None  # Or raise an exception if needed

    # Function for sending a request to the server
    @staticmethod
    def send_response(sock, request):
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
    def unpack(header_format, response_payload):
        # Implement the unpacking logic for the response payload
        header_size = struct.calcsize(header_format)
        header = struct.unpack(header_format, response_payload[:header_size])
        payload_size = header[Header.PAYLOAD_SIZE.value]
        payload = response_payload[header_size:header_size + payload_size]
        return header, payload

    @staticmethod
    def unpack_auth(header_format, response_payload):
        # Implement the unpacking logic for the response payload
        header_size = struct.calcsize(header_format)
        header = struct.unpack(header_format, response_payload[:header_size])
        payload_size = header[HeaderAuth.PAYLOAD_SIZE.value]
        payload = response_payload[header_size:header_size + payload_size]
        return header, payload

    """
    usage example on how to encrypt_message and decrypt_message
    helper = EncryptionHelper()
    message = "Hello, world!"
    key = b"your_secure_key"  # Replace with a strong, unique key
    iv = helper.get_random_bytes(AES.block_size)  # Generate a random initialization vector
"""