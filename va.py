from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions
from constants import *

class VA:
    def __init__(self):
        pass

    def verify_cert(self, ca, entity):
        cert_to_check = entity.certificate
        pk = ca.public_key

        try:
            pk.verify(cert_to_check.CA_signature, SIGN_MSG,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
        except cryptography.exceptions.InvalidSignature as e:
            return False
        return True
