import socket
from _thread import *
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions

import constants
import entity
import utils


class EntityServer:
    def __init__(self, entity, ip, port):
        self.entity = entity
        self.ip = ip
        self.port = port
        self.thread_count = 0

    def start_serv(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Setting up the server...")
        server_socket.bind((self.ip, self.port))
        server_socket.listen(5)
        print("Listening for clients...")

        while True:
            client, client_address = server_socket.accept()
            print("New client joined!", client_address)
            start_new_thread(self.threaded_client, (client,))
            self.thread_count += 1
            print('Thread Number: ' + str(self.thread_count))

        server_socket.close()

    def threaded_client(self, connection):
        connection.send(b'Welcome to the Server!')

        while True:
            data = connection.recv(constants.MESSAGE_SIZE)
            if data:
                action, content = data.decode().split(" ", 1)

                if action == "issue_to_ca":
                    if self.entity.is_CA is False:
                        connection.send(b'This server is not a CA!')
                    else:
                        cert_str = self.issue_entity(content)
                        connection.send(cert_str.encode())
                    print('finish issue_to_ca action')

                elif action == "verify_message":
                    res = self.verify_message(content)
                    if res:
                        connection.send(b'good message!')
                    else:
                        connection.send(b'bad message!')
                    print('finish verify_message action')

            else:
                print('Connection closed', )
                break

        connection.close()

    def issue_entity(self, content):
        domain, public_key_and_is_CA = content.split(' ', 1)
        public_key_str, is_CA_str = public_key_and_is_CA.split('\n-----END PUBLIC KEY-----\n ', 1)
        public_key_str += '\n-----END PUBLIC KEY-----\n'

        signer_name = self.entity.domain
        validity_date = datetime.date(datetime.now())

        is_CA = (is_CA_str == "True")
        public_key = utils.str2pub_key(public_key_str)

        cert = utils.Certificate(domain, public_key, signer_name, self.entity, is_CA, validity_date)
        CA_signature = self.entity.signature(cert.cert_to_sign().encode())
        cert.CA_signature = CA_signature

        return str(cert)

    def verify_message(self, content):
        cert, sep_letter, msg_and_signature = content.partition("]")
        cert += sep_letter
        cert = utils.str_to_class(cert)

        msg, signature = msg_and_signature.partition("***")

        # get the certification and check it
        res1 = self.verify_cert(cert)

        # get the message and check it
        res2 = self.verify_msg_content(msg, cert, signature)

        return res1 and res2

    @staticmethod
    def verify_msg_content(msg, sender_certificate, curr_signature):
        pk = sender_certificate.public_key
        try:
            pk.verify(curr_signature, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except cryptography.exceptions.InvalidSignature as e:
            return False
        return True

    @staticmethod
    def verify_cert(cert):
        entity_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        entity_server_socket.connect((constants.VA_IP, constants.VA_IP))
        data = entity_server_socket.recv(constants.MESSAGE_SIZE).decode()
        print(data)

        action = 'verify_cert'
        content = utils.cert2str(cert)
        message = action.encode() + b' ' + content.encode()

        entity_server_socket.send(message)

        data = entity_server_socket.recv(constants.MESSAGE_SIZE).decode()
        res = (data == "True")

        # close the connection
        entity_server_socket.close()
        print('------------------------------------------------------------------------------\n')
        return res

if __name__ == '__main__':
    is_CA = input("CA? [y/n]: ")
    is_CA = (is_CA == 'y')
    CA = EntityServer(entity.Entity(domain="inbal", is_CA=is_CA), constants.SERVER_HOST_IP, constants.SERVER_PORT)
    CA.start_serv()
