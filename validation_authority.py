from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions
from datetime import datetime
from constants import VALIDITY_TIME
from dateutil.relativedelta import relativedelta


class VA:
    def __init__(self, root_CA):
        self.root_CA = root_CA
        self.cancelled_certificates = []

    def verify_cert(self, cert_to_check):
        def is_val_date(cert):
            curr_date = datetime.date(datetime.now())
            if cert.validity_date + relativedelta(years=VALIDITY_TIME) < curr_date:
                return False
            return True

        if cert_to_check in self.cancelled_certificates or not is_val_date(cert_to_check):
            return False

        curr_ca = cert_to_check.my_CA

        # check the ca
        while (curr_ca is not self.root_CA) and (curr_ca.certificate is not None) and (
                curr_ca.certificate not in self.cancelled_certificates):
            curr_ca = curr_ca.certificate.my_CA

        if curr_ca is self.root_CA:
            pk = cert_to_check.my_CA.public_key
            try:
                pk.verify(cert_to_check.CA_signature, str(cert_to_check).encode(),
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
            except cryptography.exceptions.InvalidSignature as e:
                return False
            return True

        else:
            return False

    def revocation_of_certification(self, cert):
        self.cancelled_certificates.append(cert)
