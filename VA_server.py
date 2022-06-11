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
    def __init__(self, root_CA):
        self.cancelled_certificates = []
        self.root_CA = root_CA
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.thread_count = 0

    def start_serv(self):
        print("Setting up the server...")
        self.server_socket.bind((constants.VA_IP, constants.VA_PORT))
        self.server_socket.listen(5)
        print("Listening for clients...")

        while True:
            client, client_address = self.server_socket.accept()
            print("New client joined!", client_address)
            start_new_thread(self.threaded_client, (client, ))
            self.thread_count += 1
            print('Thread Number: ' + str(self.thread_count))

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
                    print('finish verify_cert action')

                elif action == "revoke_cert":
                    res = self.revoke_cert(content)
                    if res:
                        answer = "Done"
                    else:
                        answer = "Failed"
                    connection.send(answer.encode())

                    print('finish revoke_cert action')

            else:
                print('Connection closed', )
                break

        connection.close()

    def verify_cert(self, content):
        def is_val_date(cert):
            curr_date = datetime.date(datetime.now())
            if cert.validity_date + relativedelta(years=constants.VALIDITY_TIME) < curr_date:
                return False
            return True

        cert_to_check = utils.str2cert(content)

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

    def revoke_cert(self, content):
        try:
            cert = utils.str2cert(content)
            self.cancelled_certificates.append(cert)
        except Exception as e:
            print('the error: ', e)
            return False

        return True

if __name__ == '__main__':
    root_CA = Entity_server()
    va = VA()