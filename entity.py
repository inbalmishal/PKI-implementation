import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from constants import *


class Entity:
    def __init__(self, ra):
        self.private_key, self.public_key = ra.generate_keys()
        self.certificate = None

    def send_message(self, msg, to_entity):
        # send the certification

        # send the message with unique signature
        pass

    def get_message(self):
        # get the certification and check it

        # get the message and check it
        pass

    def signature(self, msg):
        signature = self.private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    def verify_message(self, msg, entity, signature):
        pk = entity.certificate.public_key
        try:
            pk.verify(signature, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except cryptography.exceptions.InvalidSignature as e:
            return False

        return True
