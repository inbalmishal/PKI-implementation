import utils

class Certificate:
    def __init__(self, domain, public_key, signer_name, my_CA, is_CA, validity_date, ca_signature=None):
        self.domain = domain
        self.public_key = public_key
        self.signer_name = signer_name
        self.my_CA = my_CA
        self.CA_signature = ca_signature
        self.is_CA = is_CA
        self.validity_date = validity_date

    def __str__(self):
        pkstring = utils.pub_key2str(self.public_key)
        return f"[domain:{str(self.domain)}, public_key:{pkstring}, signer_name:{str(self.signer_name)}, " \
               f"old_CA:{str(self.my_CA)}, CA_signature:{str(self.CA_signature)}, is_CA:{str(self.is_CA)}, " \
               f"validity_date:{str(self.validity_date)}]"

    def cert_to_sign(self):
        pkstring = utils.pub_key2str(self.public_key)
        return f"[domain:{str(self.domain)}, public_key:{pkstring}, signer_name:{str(self.signer_name)}, " \
               f"old_CA:{str(self.my_CA)}, is_CA:{str(self.is_CA)}, validity_date:{str(self.validity_date)}]"


