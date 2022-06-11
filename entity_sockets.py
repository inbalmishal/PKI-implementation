import socket
from threading import *
from _thread import *
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions

import constants
import utils


class EntitySockets:
    def __init__(self, entity, ip, port):
        self.entity = entity
        self.ip = ip
        self.port = port
        self.clients_thread_count = 0
        self.cli_thread = Thread(target=self.cli_start)
        self.serv_thread = Thread(target=self.start_serv)

    def start(self):
        self.cli_thread.start()
        self.serv_thread.start()

    def cli_start(self):
        while True:
            print("what do you want to do? (choose a number)")
            print("[1] - get a certificate from root_CA")
            print("[2] - send message to other root_CA to check its validity")
            print("[3] - turn into CA using root CA")
            print("[4] - get a certificate from any CA")
            print("[other] - exit client side")
            res = input()
            if res == '1':
                self.issue_on_CA()
            elif res == '2':
                msg = input("enter your message to check: ")
                self.send_message(msg)
            elif res == '3':
                self.entity.is_CA = True
                self.issue_on_CA()
            elif res == '4':
                ca_ip = input("Enter CA ip: ")
                ca_port = int(input("Enter CA port: "))
                self.issue_on_CA(ca_ip, ca_port)
            else:
                return

    def issue_on_CA(self, ca_ip=constants.ROOT_CA_IP, ca_port=constants.ROOT_CA_PORT):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ca_ip, ca_port))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(data)

        action = 'issue_to_ca'
        content = self.entity.domain + ' ' + utils.pub_key2str(self.entity.public_key) + ' ' + str(self.entity.is_CA)
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        if utils.is_cert_type(data):
            self.entity.certificate = utils.str2cert(data)
            print('action succeeded:)')
        else:
            print('action failed:(')

        # close the connection
        client_socket.close()
        print('------------------------------------------------------------------------------\n')

    def send_message(self, msg_content):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((constants.ROOT_CA_IP, constants.ROOT_CA_PORT))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(data)

        action = 'verify_message'
        content = utils.cert2str(self.entity.certificate) + constants.SEP_STRING + msg_content + constants.SEP_STRING \
                  + str(self.entity.signature(msg_content.encode()))
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        print(data)

        # close the connection
        client_socket.close()
        print('------------------------------------------------------------------------------\n')

    # -------------------------------------------------------------------------

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
            self.clients_thread_count += 1
            print('Thread Number: ' + str(self.clients_thread_count))

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

                elif action == "get_cert":
                    res = self.send_cert()
                    connection.send(res.encode())
                    print('finish send_cert action')

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

        cert = utils.Certificate(domain, public_key, signer_name, self.entity.domain,
                                 self.ip, self.port, is_CA, validity_date)
        CA_signature = self.entity.signature(cert.cert_to_sign().encode())
        cert.CA_signature = CA_signature

        return str(cert)

    def verify_message(self, content):
        cert, sep_letter, msg_and_signature = content.partition("]" + constants.SEP_STRING)
        cert += ']'
        cert = utils.str_to_class(cert)

        msg, sep_string, signature = msg_and_signature.partition(constants.SEP_STRING)

        # get the certification and check it
        res1 = self.verify_cert(cert)

        # get the message and check it
        res2 = self.verify_msg_content(msg.encode(), cert, signature.encode())

        return res1 and res2

    def send_cert(self):
        return utils.cert2str(self.entity.certificate)

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
        entity_server_socket.connect((constants.VA_IP, constants.VA_PORT))
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

