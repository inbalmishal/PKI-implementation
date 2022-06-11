from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import utils


class Entity:
    def __init__(self, domain, is_CA=False):
        self.is_CA = is_CA
        self.domain = domain
        self.private_key, self.public_key = utils.generate_keys()
        self.certificate = None

    def signature(self, msg):
        signature = self.private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature
