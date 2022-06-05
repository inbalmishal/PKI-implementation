from cryptography.hazmat.primitives.asymmetric import rsa
from constants import *

class RA:
    def __init__(self):
        pass

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE)

        public_key = private_key.public_key()


        return private_key, public_key
