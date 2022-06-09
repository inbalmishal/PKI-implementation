class Certificate:
    def __init__(self, domain, public_key, signer_name, old_CA, is_CA, validity_date, ca_signature=None):
        self.domain = domain
        self.public_key = public_key
        self.signer_name = signer_name
        self.old_CA = old_CA
        self.CA_signature = ca_signature
        self.is_CA = is_CA
        self.validity_date = validity_date

    def __str__(self):
        return f"[domain:{str(self.domain)}, public_key:{str(self.public_key)}, signer_name:{str(self.signer_name)}, " \
               f"old_CA:{str(self.old_CA)}, is_CA:{str(self.is_CA)}, " \
               f"validity_date:{str(self.validity_date)}]"
