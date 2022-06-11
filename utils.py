import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from constants import *
from certificate import Certificate


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE)

    public_key = private_key.public_key()
    return private_key, public_key


def pub_key2str(pk):
    pem_public = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public.decode()


def pr_key2str(prk):
    pem_private = prk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # print(pem_private[pem_private.find(b'\n')+1:pem_private.find(b'\n-----END RSA PRIVATE KEY-----\n')])
    return pem_private.decode()


def str2pr_key(pem_string):
    private_key = serialization.load_pem_private_key(
        pem_string,
        password=None
    )
    return private_key


def str2pub_key(pem_string):
    public_key = serialization.load_pem_public_key(
        pem_string.encode()
    )
    return public_key


def is_cert_type(string):
    if '[domain:' in string and ', public_key:' in string and ', signer_name:' in string and ', old_CA:' in string and \
            ', CA_signature:' in string and ', is_CA:' in string and ', validity_date:' in string and ']' in string:
        return True
    return False


def cert2str(cert):
    return str(cert)


def str2cert(string):
    if not is_cert_type(string):
        raise Exception("not a certificate type")
    else:
        domain = string[8:string.find(',')]
        public_key = string[string.find(', public_key:') + len(', public_key:'):string.find(',', 2)]
        signer_name = string[string.find(', signer_name:') + len(', signer_name:'):string.find(',', 3)]
        old_CA = string[string.find(', old_CA:') + len(', old_CA:'):string.find(',', 4)]
        is_CA = string[string.find(', is_CA:') + len(', is_CA:'):string.find(',', 5)]
        validity_date = string[string.find(', validity_date:') + len(', validity_date:'):string.find(',', 6)]
        ca_signature = string[string.find(', ca_signature:') + len(', ca_signature:'):string.find(',', 7)]
        return Certificate(domain, public_key, signer_name, old_CA, is_CA, validity_date, ca_signature)


def class_to_str(object):
    if type(object) == _RSAPrivateKey:
        return pr_key2str(object)
    if type(object) == _RSAPublicKey:
        return pub_key2str(object)
    if type(object) == Certificate:
        return cert2str(object)

    json_string = json.dumps(object)
    return json_string


def str_to_class(string):
    if is_cert_type(string):
        return str2cert(string)
    else:
        object = json.loads(string)
        return object
