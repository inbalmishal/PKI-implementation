from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions
import socket
from _thread import *
from datetime import datetime

from dateutil.relativedelta import relativedelta

import constants
import utils


class VA:
    def __init__(self, root_CA_domain, ip, port):
        self.cancelled_certificates = []
        self.root_CA_domain = root_CA_domain
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.thread_count = 0
        self.ip = ip
        self.port = port

    def start_serv(self):
        print(f"{utils.Colors.server}Setting up the server...{utils.Colors.RESET}")
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
        print(f"{utils.Colors.server}Listening for clients...{utils.Colors.RESET}")

        while True:
            client, client_address = self.server_socket.accept()
            print(f"{utils.Colors.server}New client joined! {client_address}{utils.Colors.RESET}")
            start_new_thread(self.threaded_client, (client,))
            self.thread_count += 1
            print(f"{utils.Colors.server}Thread Number:  {str(self.thread_count)}{utils.Colors.RESET}")

        server_socket.close()

    def threaded_client(self, connection):
        connection.send(b'Welcome to the VA Server!')

        while True:
            data = connection.recv(constants.MESSAGE_SIZE)
            if data:
                action, content = data.decode().split(" ", 1)

                if action == "verify_cert":
                    res = self.verify_cert(content)
                    connection.send(str(res).encode())
                    print(f"{utils.Colors.server}finish verify_cert action{utils.Colors.RESET}")

                elif action == "revoke_cert":
                    res = self.revoke_cert(content)
                    if res:
                        answer = "Done"
                    else:
                        answer = "Failed"
                    connection.send(answer.encode())

                    print(f"{utils.Colors.server}finish revoke_cert action{utils.Colors.RESET}")

            else:
                print(f"{utils.Colors.server}Connection closed{utils.Colors.RESET}", )
                break

        connection.close()

    def verify_cert(self, cert_str):
        def is_val_date(cert):
            curr_date = datetime.date(datetime.now())
            if datetime.date(cert.validity_date + relativedelta(years=constants.VALIDITY_TIME)) < curr_date:
                return False
            return True

        cert_to_check = utils.str2cert(cert_str)

        if cert_str in self.cancelled_certificates or not is_val_date(cert_to_check):
            return False

        if cert_to_check.my_CA_domain == self.root_CA_domain:
            return True

        # initialize
        old_cert = cert_to_check
        ca_cert = utils.str2cert(self.get_cert(cert_to_check.my_CA_ip, cert_to_check.my_CA_port))

        # check the CA
        while old_cert.my_CA_domain != self.root_CA_domain:

            if utils.cert2str(ca_cert) in self.cancelled_certificates or not is_val_date(ca_cert):
                return False

            # verify the signature
            pk = ca_cert.public_key
            try:
                pk.verify(old_cert.CA_signature, old_cert.cert_to_sign().encode(),
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
            except cryptography.exceptions.InvalidSignature:
                return False

            old_cert = ca_cert
            ca_cert = utils.str2cert(self.get_cert(ca_cert.my_CA_ip, ca_cert.my_CA_port))

        # when we in the root CA
        if old_cert.my_CA_domain == self.root_CA_domain:
            pk = ca_cert.public_key
            try:
                pk.verify(old_cert.CA_signature, old_cert.cert_to_sign().encode(),
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
            except cryptography.exceptions.InvalidSignature:
                return False
            return True

        return False

    @staticmethod
    def get_cert(ip, port) -> str:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(f"{utils.Colors.server}{data}{utils.Colors.RESET}")

        client_socket.send(b'get_cert None')

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        # close the connection
        client_socket.close()
        return data

    def revoke_cert(self, cert_str):
        try:
            cert = utils.str2cert(cert_str)
            if cert.domain == self.root_CA_domain:
                raise Exception("Root_CA can't be canceled!!")
            else:
                self.cancelled_certificates.append(cert_str)
        except Exception as e:
            print(f"{utils.Colors.server}the error: {e}{utils.Colors.RESET}")
            return False

        return True


if __name__ == '__main__':
    va = VA(constants.ROOT_CA_DOMAIN, constants.VA_IP, constants.VA_PORT)
    va.start_serv()
