import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from registration_authority import RA


class Entity:
    def __init__(self, domain):
        self.domain = domain
        self.private_key, self.public_key = RA.generate_keys()
        self.certificate = None

    def check_all_message(self, va, msg, sender):
        # get the certification and check it
        res1 = va.verify_cert(sender.certificate)

        # get the message and check it
        res2 = self.verify_message(msg, sender, sender.signature(msg))

        return res1 and res2

    def signature(self, msg):
        signature = self.private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    @staticmethod
    def verify_message(msg, sender_entity, curr_signature):
        pk = sender_entity.certificate.public_key
        try:
            pk.verify(curr_signature, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except cryptography.exceptions.InvalidSignature as e:
            return False

        return True

