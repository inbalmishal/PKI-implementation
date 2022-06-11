import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from datetime import datetime

import constants
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
    if '[domain:' in string and ', public_key:' in string and ', signer_name:' in string and\
            ', my_CA_domain:' in string and ', my_CA_ip:' in string and ', my_CA_port:' in string and\
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
        a = string[
            string.find(', public_key:') + len(', public_key:'):string.find('\n-----END PUBLIC KEY-----\n, ') + len(
                '\n-----END PUBLIC KEY-----\n')]
        public_key = str2pub_key(a)
        signer_name = string[string.find(', signer_name:') + len(', signer_name:'):string.find(', my_CA_domain:')]
        my_CA_domain = string[string.find(', my_CA_domain:') + len(', my_CA_domain:'):string.find(', my_CA_ip:')]
        my_CA_ip = string[string.find(', my_CA_ip:') + len(', my_CA_ip:'):string.find(', my_CA_port:')]
        my_CA_port = string[string.find(', my_CA_port:') + len(', my_CA_port:'):string.find(', CA_signature:')]
        ca_signature = string[string.find(', CA_signature:') + len(', CA_signature:'):string.find(', is_CA:')]
        is_CA_str = string[string.find(', is_CA:') + len(', is_CA:'):string.find(', validity_date:')]
        is_CA = (is_CA_str == 'True')
        validity_date = datetime.strptime(string[string.find(', validity_date:') + len(', validity_date:'):-1],
                                          constants.DATE_FORMAT)

        return Certificate(domain, public_key, signer_name, my_CA_domain, my_CA_ip, my_CA_port, is_CA, validity_date,
                           ca_signature)


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
