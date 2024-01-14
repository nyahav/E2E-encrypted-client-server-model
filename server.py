import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# פונקציה להצפנת הודעה ב-AES-CBC
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

# פונקציה לפענוח הודעה מוצפנת ב-AES-CBC
def decrypt_message(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.rstrip(b'\0')  # להסיר padding

# פונקציה לשליחת בקשה לשרת
def send_request(sock, request):
    sock.send(request.encode())

# פונקציה לקבלת תשובה מהשרת
def receive_response(sock):
    response = sock.recv(1024).decode()
    return response

# פונקציה לטיפול בשגיאה מצד השרת
def handle_server_error():
    print("server responded with an error")

# פונקציה לבצע בקשת רישום לשרת אימות
def register_to_auth_server(sock, username):
    request = f"REGISTER {username}"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Registration successful")

# פונקציה לשליחת בקשת רשימת שרתי הודעות לשרת אימות
def get_message_servers_list(sock):
    request = "GET_SERVERS_LIST"
    send_request(sock, request)
    response = receive_response(sock)
    if response == "ERROR":
        handle_server_error()
    else:
        print("Message servers list:")
        print(response)

# פונקציה לקבלת מפתח AES מהשרת
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

# פונקציה לשליחת הודעה לשרת הודעות
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

# פונקציה לבצע קבלת הודעה מהשרת הודעות
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

# פונקציה לבצע קריאה לשרת הודעות
def main():
    server_address = ('127.0.0.1', 1234)  # להחליף עם פרטי השרת המתאימים
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)

    username = "user123"
    register_to_auth_server(sock, username)

    get_message_servers_list(sock)

    server_id = "server1"  # לבחור שרת מהרשימה
    aes_key = get_aes_key_from_message_server(sock, server_id)
    if aes_key:
        ticket = "12345"  # להשים פרטי כרטיס
        message_to_send = "Hello, server!"
        send_message_to_server(sock, message_to_send, aes_key, ticket)

        receive_message_from_server(sock, aes_key, ticket)

    sock.close()

if __name__ == "__main__":
    main()
