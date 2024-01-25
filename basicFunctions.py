import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
   
#move both function into class so can be access from all entnties
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

def get_random_bytes(length):
    if length not in [16, 32]:
     raise ValueError("Invalid length. Please specify 16 or 32 bytes.")

    return secrets.token_bytes(length)