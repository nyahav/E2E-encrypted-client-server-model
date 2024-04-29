# E2E-Encrypted Client-Server Model


# Project Description


This project implements a simple end-to-end encrypted client-server model using Python. It leverages the socket and pycryptodome libraries to build secure communication channels ️.

# Project by: Yahav Nir & Elad Shahar

# Project Architecture

Imagine a classic client-server setup:

    The client connects to the authentication server for identity verification (like showing your ID at a club ).
    After successful authentication, the client receives a secret key for secure communication with the message server (think of it as a secret handshake ).
    The client securely sends the key to the message server.
    Now, the client can send encrypted messages to the message server, which decrypts and displays them on the console (like whispering secrets ).

Key Features

    End-to-end encryption with AES-CBC mode (fancy way of saying your messages are scrambled and unreadable by anyone in between)
    Simple and user-friendly (easy to set up and use)
    Written in Python (a popular and beginner-friendly programming language)

Usage

Before diving in, install the required libraries:
Bash

pip install socket pip install pycryptodome

Use code with caution.

Then, run the client and server scripts:
Bash

python client.py
python server.py

Use code with caution.

This establishes a secure communication channel between the client and server, allowing them to exchange encrypted messages.

Examples

    Sending a message from the client:

Python

client.send_message("Hello, world!")

Use code with caution.

    Receiving a message from the server:

Python

message = server.receive_message()

Use code with caution.

    Printing the message:

Python

print(message)

Use code with caution.

Future Work

Here are some ideas for further development:

    Add support for multiple users (so you can have a secret chat party )
    Implement additional encryption algorithms (for extra security layers ️)
    Explore alternative authentication methods (like using existing login services )
