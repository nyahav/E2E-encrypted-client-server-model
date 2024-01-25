import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
   
#move both function into class so can be access from all entnties
# Function for encrypting a message using AES-CBC
def encrypt_message(message, key, iv):
    padded_message = pad(message.encode(), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Function for decrypting a message encrypted with AES-CBC
def decrypt_message(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, AES.block_size)
    return unpadded_message.decode()

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

def get_random_bytes(length):
    if length not in [16, 32]:
     raise ValueError("Invalid length. Please specify 16 or 32 bytes.")
    return secrets.token_bytes(length)

"""
usage example on how to encrypt_message and decrypt_message
helper = EncryptionHelper()
message = "Hello, world!"
key = b"your_secure_key"  # Replace with a strong, unique key
iv = helper.get_random_bytes(AES.block_size)  # Generate a random initialization vector

encrypted_message = helper.encrypt_message(message, key, iv)
decrypted_message = helper.decrypt_message(encrypted_message, key, iv)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message.hex()}")
print(f"Decrypted message: {decrypted_message}")
"""