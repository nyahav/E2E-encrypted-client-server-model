# all defenitions
from abc import ABC, abstractmethod
from enum import *
import struct


class HeadersFormat(Enum):
    MESSAGE_FORMAT = "<16sHHI"
    CLIENT_FORMAT = "<16sHHI"
    AUTH_RESP_HEADER = "<BHL"

# Constants
class Color(Enum):
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'


def colored_text(text, color):
    return f"{color.value}{text}{Color.RESET.value}"


# Example usage:
# print(colored_text("This is red text", Color.RED))

# Values
SERVERS_FILE = "srv.info"
VERSION = 24
PORT_INFO_FILE_PATH = "port.info"
HOST = "127.0.0.1"  # localhost
MAX_PORT_VALUE = 65535


# Header placements
class Header(Enum):
    CLIENT_ID = 0
    VERSION = 1
    CODE = 2
    PAYLOAD_SIZE = 3
    #issue here,payloadsize is 2 at authresponse
class HeaderAuth(Enum):
    VERSION = 0
    CODE = 1
    PAYLOAD_SIZE = 2

#  Lengthss
UUID_LEN = 16
SERVER_ID_LENGTH = 16
CLIENT_ID_LEN = 16
USERNAME_LEN = 255
PUBLIC_KEY_LEN = 160
VERSION_LEN = 1
CODE_LEN = 2
PAYLOADSIZE_LEN = 4
MESSAGE_TYPE_LEN = 1
MESSAGE_CONTENT_LEN = 4
MESSAGE_ID_LEN = 4
# Request Lengths
REQUEST_HEADER_LEN = CLIENT_ID_LEN + VERSION_LEN + CODE_LEN + PAYLOADSIZE_LEN
# Response Lengths
RESPONSE_HEADER_LEN = VERSION_LEN + CODE_LEN + PAYLOADSIZE_LEN


# The available request codes which are sent to authentication server by the client.
class ClientRequestToAuth(IntEnum):
    REGISTER_CLIENT = 1024,
    REQUEST_LIST_OF_MESSAGE_SERVERS = 1026,
    GET_SYMETRIC_KEY = 1027,


# The available request codes which are sent to message server by the client.
class RequestMessage(IntEnum):
    SEND_SYMETRIC_KEY = 1028,
    SEND_MESSAGE = 1029,


# The available response codes which the authentication server  send to a client.


class ResponseAuth(IntEnum):
    REGISTER_SUCCESS_RESP = 1600,
    REGISTER_FAILURE_RESP = 1601,
    RESPONSE_MESSAGE_SERVERS_LIST = 1602,
    RESPONSE_SYMETRIC_KEY = 1603,


# The available response codes which the message server  send to a client.
class ResponseMessage(IntEnum):
    APPROVE_SYMETRIC_KEY = 1604,
    APPROVE_MESSAGE_RECIVED = 1605,
    GENERAL_ERROR = 1609,


class MessageServerToAuth(IntEnum):
    REGISTER_MESSAGE_SERVER = 1025,


class Request(ABC):
    def __init__(self):
        self.version = VERSION

    @classmethod
    def pack(cls, client_id, version, code, payload):
        header_data = cls.header.pack(
            client_id, version, code, len(payload)
        )
        return header_data + payload

    @classmethod
    def unpack_response(cls, response_payload):
        # Implement the unpacking logic for the response payload
        header_size = struct.calcsize(cls.header.format)
        header = struct.unpack(cls.header.format, response_payload[:header_size])

        server_response = {
            'Version': header[1],
            'Code': header[2],
            'Payload_Size': header[3],
            'Payload': response_payload[header_size:],
        }

        return server_response