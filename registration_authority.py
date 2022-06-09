from cryptography.hazmat.primitives.asymmetric import rsa
from constants import *


class RA:
    def registration(self):
        # TODO finish it
        pass

    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE)

        public_key = private_key.public_key()
        return private_key, public_key
