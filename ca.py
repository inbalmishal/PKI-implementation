from entity import Entity
from certificate import Certificate
from datetime import datetime
from constants import *


class CA(Entity):
    def __init__(self, ra):
        super().__init__(ra)
        self.entities = {}  # dictionary. domain -> certificate

    def issue_entity(self, entity, domain, public_key, signer_name, is_CA):
        validity_date = datetime.date(datetime.now())
        CA_signature = self.signature(SIGN_MSG)
        cert = Certificate(domain, public_key, signer_name, CA_signature, is_CA, validity_date)

        self.entities[cert.domain] = cert
        entity.certificate = cert
        return cert

    def check_certificate(self, cert):
        pass


