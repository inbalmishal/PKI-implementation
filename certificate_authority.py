from entity import Entity
from certificate import Certificate
from datetime import datetime


class CA(Entity):
    def __init__(self, domain):
        super().__init__(domain)

    def issue_entity(self, entity, public_key, signer_name, is_CA):
        validity_date = datetime.date(datetime.now())
        cert = Certificate(entity.domain, public_key, signer_name, self, is_CA, validity_date)
        CA_signature = self.signature(str(cert).encode())
        cert.CA_signature = CA_signature
        entity.certificate = cert
        return cert




