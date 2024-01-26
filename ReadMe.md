E2E-Encrypted Client-Server Model

Project Description

This project implements a simple end-to-end encrypted client-server model using the Python programming language. The project uses the socket and pycryptodome libraries to implement the client and server components.

Project Architecture

The project architecture is based on a client-server model. The client initiates a connection with the authentication server, which validates the client's identity. After successful authentication, the client receives a symmetric key for communication with the message server. The client then sends the symmetric key to the message server, after which it can send encrypted messages to the message server. The message server's role is to receive messages from clients and print them to the console.

Key Features

    End-to-end encryption using the AES-CBC mode
    Simple and easy to use
    Written in Python

Usage

To use the project, first install the required libraries:

pip install socket
pip install pycryptodome

Then, run the client and server scripts:

python client.py
python server.py

The client and server will then communicate with each other using end-to-end encryption.

Examples

The following are some examples of how to use the project:

# Send a message from the client to the server
client.send_message("Hello, world!")

# Receive a message from the server
message = server.receive_message()

# Print the message to the console
print(message)

Future Work

Some possible future work for this project include:

    Adding support for multiple users
    Adding support for different encryption algorithms
    Adding support for authentication using other methods, such as OAuth or OpenID Connect