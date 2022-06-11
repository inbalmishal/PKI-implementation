from datetime import datetime

import constants
import utils


class Certificate:
    def __init__(self, domain, public_key, signer_name, my_CA_domain, my_CA_ip, my_CA_port, is_CA, validity_date,
                 ca_signature=b''):
        self.domain = domain
        self.public_key = public_key
        self.signer_name = signer_name
        self.my_CA_domain = my_CA_domain
        self.my_CA_ip = my_CA_ip
        self.my_CA_port = my_CA_port
        self.CA_signature = ca_signature
        self.is_CA = is_CA
        self.validity_date = validity_date

    def __str__(self):
        pkstring = utils.pub_key2str(self.public_key)
        val_date_str = self.validity_date.strftime(constants.DATE_FORMAT)
        return f"[domain:{str(self.domain)}, public_key:{pkstring}, signer_name:{str(self.signer_name)}, " \
               f"my_CA_domain:{str(self.my_CA_domain)}, my_CA_ip:{str(self.my_CA_ip)}, " \
               f"my_CA_port:{str(self.my_CA_port)}, CA_signature:{self.CA_signature.hex()}, is_CA:{str(self.is_CA)}" \
               f", validity_date:{val_date_str}]"

    def cert_to_sign(self):
        pkstring = utils.pub_key2str(self.public_key)
        return f"[domain:{str(self.domain)}, public_key:{pkstring}, signer_name:{str(self.signer_name)}" \
               f", my_CA_domain:{str(self.my_CA_domain)}, my_CA_ip:{str(self.my_CA_ip)}" \
               f", my_CA_port:{str(self.my_CA_port)}, is_CA:{str(self.is_CA)}, validity_date:{str(self.validity_date)}]"

