import socket
import uuid

class Client:
    def __init__(self):
        self.auth_server_address = self.read_auth_server_address()
        self.client_id, self.client_name, self.client_aes_key = self.read_client_info()
        self.ticket = None

    def read_auth_server_address(self):
        try:
            with open("me.info", "r") as file:
                address = file.readline().strip()
                return address
        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def read_client_info(self):
        try:
            with open("me.info", "r") as file:
                address = file.readline().strip()
                name = file.readline().strip()
                client_id = file.readline().strip()
                return client_id, name, address
        except FileNotFoundError:
            print("Error: me.info file not found.")
            exit()

    def register_with_auth_server(self):
        # TODO: Implement client registration logic with the authentication server

    def request_server_list(self):
        # TODO: Implement client's request for the list of servers from the authentication server

    def request_aes_key(self):
        # TODO: Implement client's request for an AES key from the authentication server

    def communicate_with_message_server(self):
        # TODO: Implement communication with the message server using the obtained AES key

if __name__ == "__main__":
    client = Client()
    client.register_with_auth_server()
    client.request_server_list()
    client.request_aes_key()
    client.communicate_with_message_server()
