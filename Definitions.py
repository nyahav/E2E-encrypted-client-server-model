# all defenitions
from enum import *

# Constants

# Values
VERSION = 1
PORT_INFO_FILE_PATH = "port.info"
HOST = "127.0.0.1"  # localhost
MAX_PORT_VALUE = 65535
DATABASE_NAME = "server.db"

#  Lengths
UUID_LEN = 16
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
#Response Lengths
RESPONSE_HEADER_LEN=VERSION_LEN+CODE_LEN+PAYLOADSIZE_LEN

# The available request codes which are taking care by the authentication server.
class RequestAuth(IntEnum):
    REGISTER_CLIENT = 1025,
    REGISTER_SERVER = 1027,
    REQUEST_MESSAGE_SERVERS=1026,
    GET_SYMETRIC_REQ = 1027,
    
# The available request codes which are taking care by the message server.
class RequestAuth(IntEnum):
    GET_SYMETRIC_REQ = 1028, 
    SEND_MESSAGE = 1029, 

# The available response codes which the authentication server can send to a client.
class ResponseAuth(IntEnum):
    REGISTER_SUCCESS_RESP = 1600,
    REGISTER_FAILURE_RESP = 1601,
    RESPONSE_MESSAGE_SERVERS=1602,
    RESPONSE_SYMETRIC_REQ = 1603,
 # The available response codes which the authentication server can send to a client.
class ResponseAuth(IntEnum):
    APPROVE_SYMETRIC_KEY = 1604,
    APPROVE_MESSAGE_RECIVED = 1605,
    GENERAL_ERROR=1609,
   
# The available messages' types the server is taking care of.
class MessageTypes(IntEnum):
    ASK_SYM_KEY = 1,
    SEND_SYM_KEY = 2,
    SEND_TEXT_MSG = 3,
    SEND_TEXT_FILE = 4