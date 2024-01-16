import socket
import uuid
import AutoServer
import MessageServer
from Definitions import *


class Request:
    def __init__(self, client_id, version, code, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

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

    def handle_register_request(self, request):
        # Validate the request
        if request.code != 1025:
            return AutoServer(AutoServer.REGISTER_FAILURE_RESP)

        # Get the client name and password
        client_name = request.payload[:255]
        password = request.payload[255:]

        # Register the client with the authentication server
        client_id = uuid.uuid4()
        AutoServer.register_client(client_id, client_name, password)

        return AutoServer(AutoServer.REGISTER_SUCCESS_RESP, client_id=client_id)

    def register_with_auth_server(self):
        # Create a request object
        request = Request(
            client_id=self.client_id,
            version=VERSION,
            code=RequestAuth.REGISTER_CLIENT,
            payload_size=255 + len(self.client_name) + len(self.client_password),
            payload=self.client_name.encode() + self.client_password.encode()
        )

        # Set the payload
        request.payload[:255] = self.client_name
        request.payload[255:] = self.client_password

        # Send the request to the authentication server
        response = self.send_request(request)

        # Check the response code
        if response.code != 1600:
            print("Error: Registration failed.")
            return

        # Save the client ID
        self.client_id = response.client_id

        print("Registration successful.")

    def request_server_list(self):
    #Requests the list of servers from the authentication server.

    # Create a request object with appropriate code for server list request
        request = Request(
            client_id=self.client_id,
            version=24,  
            code=AutoServer. REQUEST_MESSAGE_SERVERS
            payload_size=0,  # No payload needed for this request
            payload=b""
        )

        # Send the request to the authentication server
        response = self.send_request(request)

        # Process the response, assuming it contains a list of servers
        server_list = response.payload  # Assuming payload holds the server list
        # Do something with the server list here

    def request_aes_key(self, server_id):
    #Requests an AES key from the authentication server for a specific server.

        # Create a request object with appropriate code for AES key request
        request = Request(
            client_id=self.client_id,
            version=24, 
            code= AutoServer.RESPONSE_SYMETRIC_REQ
            payload_size=len(server_id)
            payload=server_id.encode()  # Assuming server ID is a string
        )
        # Send the request to the authentication server
        response = self.send_request(request)
        # Process the response, assuming it contains the AES key
        aes_key = response.payload  # Assuming payload holds the AES key
        # Store or use the AES key for communication with the specified server


    def communicate_with_message_server(self):
        # TODO: Implement communication with the message server using the obtained AES key
        pass

if __name__ == "__main__":
    client = Client()
    client.register_with_auth_server()
    client.request_server_list()
    client.request_aes_key()
    client.communicate_with_message_server()
