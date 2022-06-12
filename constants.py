PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048
VALIDITY_TIME = 1

ROOT_CA_IP = "127.0.0.1"
ROOT_CA_PORT = 65430
ROOT_CA_DOMAIN = "root_CA"

VA_IP = "127.0.0.8"
VA_PORT = 65431

EN1_IP = "127.0.0.3"
EN1_PORT = 65432

# ------------------------- For test -------------------------
EN2_IP = "127.0.0.4"
EN2_PORT = 65433

EN3_IP = "127.0.0.5"
EN3_PORT = 65434
# ------------------------------------------------------------

SEP_STRING = '***'
DATE_FORMAT = "%Y-%m-%d"
MESSAGE_SIZE = 1000000000


class Colors:
    server = '\033[92m'  # GREEN
    client = '\033[94m'  # BLUE
    RESET = '\033[0m'  # RESET COLOR
