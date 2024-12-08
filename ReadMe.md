# E2E-Encrypted Client-Server Model
---
This project showcases a simple end-to-end encrypted (E2EE) client-server communication model built using Python. It leverages the socket and pycryptodome libraries to establish secure communication channels, ensuring privacy and confidentiality.

🎥 Watch the Demo (in Hebrew): YouTube Video
📖 Project by: Yahav Nir & Elad Shahar
🌐 Project Architecture
---
This model mimics a classic client-server setup with an added layer of encryption:

    Authentication Phase
        The client connects to the authentication server for identity verification (like presenting your ID).
        Upon successful authentication, the client receives a secret key to enable secure communication.

    Key Exchange Phase
        The client securely transmits the key to the message server.

    Secure Messaging Phase
        The client sends encrypted messages to the message server.
        The message server decrypts and displays the messages (like a private conversation).
---
🔑 Key Features
End-to-End Encryption

    Uses AES-CBC mode, a robust encryption standard to ensure that all messages remain secure and unreadable to any intermediaries.

User-Friendly

    Simple setup with Python, ideal for beginners or anyone interested in secure communications.

Cross-Platform Compatibility

    Written in Python, making it compatible with any system that supports the language.
---
🚀 Usage
1. Install the Required Libraries

Install dependencies using pip:

pip install socket pycryptodome

2. Run the Client and Server Scripts

Start the server and client processes to establish a secure communication channel:

python server.py
python client.py

3. Exchange Encrypted Messages
Sending a Message (Client Side):

client.send_message("Hello, world!")

Receiving a Message (Server Side):

message = server.receive_message()

Printing the Message:

print(message)
---
💡 Examples
Client Console Output:

[AUTH] Successfully authenticated.
[KEY] Encryption key shared with the server.
[SEND] Message sent: Hello, world!

Server Console Output:

[RECEIVED] Encrypted Message: b'...'
[DECRYPTED] Message: Hello, world!
---
📘 Future Work

Here are some ideas for expanding the project:

    Multi-User Support: Allow multiple clients to connect for group messaging.
    Enhanced Security: Explore and implement additional encryption algorithms for layered security.
    Alternative Authentication Methods: Integrate modern authentication services like OAuth2 or biometric verification.
---
🛠️ Tech Stack

    Programming Language: Python
    Encryption Library: pycryptodome
    Networking: socket
---
📎 Contributing

Feel free to fork this repository and submit pull requests for improvements or bug fixes. Contributions are always welcome! 😊
⚠️ Disclaimer

    This project is for educational purposes only.
    Exercise caution when using the code in production environments.
---
Happy coding🎉 
