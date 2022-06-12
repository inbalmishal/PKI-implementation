import socket
from threading import *
from _thread import *
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions
import time
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
        self.serv_thread.start()
        time.sleep(1)
        self.cli_thread.start()

    # -----------------------------------client functions--------------------------------------

    def cli_start(self):
        while True:
            print(f"{constants.Colors.client}what do you want to do? (choose a number){constants.Colors.RESET}")
            print(f"{constants.Colors.client}[1] - get a certificate from root_CA{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[2] - get a certificate from any CA{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[3] - send message to root_CA to check its validity{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[4] - send message to other entity to check its validity{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[5] - turn into CA using root CA{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[6] - turn into CA using any CA{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[7] - revoke my certificate{constants.Colors.RESET}")
            print(f"{constants.Colors.client}[other] - stay in the menu{constants.Colors.RESET}")
            res = input()
            if res == '1':
                self.issue_on_CA()
            elif res == '2':
                ca_ip = input(f"{constants.Colors.client}Enter CA ip: {constants.Colors.RESET}")
                ca_port = int(input(f"{constants.Colors.client}Enter CA port: {constants.Colors.RESET}"))
                self.issue_on_CA(ca_ip, ca_port)
            elif res == '3':
                msg = input(f"{constants.Colors.client}enter your message to check: {constants.Colors.RESET}")
                self.send_message(msg)
            elif res == '4':
                msg = input(f"{constants.Colors.client}enter your message to check: {constants.Colors.RESET}")
                en_ip = input(f"{constants.Colors.client}Enter entity ip: {constants.Colors.RESET}")
                en_port = int(input(f"{constants.Colors.client}Enter entity port: {constants.Colors.RESET}"))
                self.send_message(msg, en_ip, en_port)
            elif res == '5':
                self.entity.is_CA = True
                self.issue_on_CA()
            elif res == '6':
                self.entity.is_CA = True
                ca_ip = input(f"{constants.Colors.client}Enter CA ip: {constants.Colors.RESET}")
                ca_port = int(input(f"{constants.Colors.client}Enter CA port: {constants.Colors.RESET}"))
                self.issue_on_CA(ca_ip, ca_port)
            elif res == '7':
                self.revoke_my_cert(constants.VA_IP, constants.VA_PORT)

    def issue_on_CA(self, ca_ip=constants.ROOT_CA_IP, ca_port=constants.ROOT_CA_PORT):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ca_ip, ca_port))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        action = 'issue_to_ca'
        content = self.entity.domain + ' ' + utils.pub_key2str(self.entity.public_key) + ' ' + str(self.entity.is_CA)
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        if utils.is_cert_type(data):
            self.entity.certificate = utils.str2cert(data)
            print(f"{constants.Colors.client}action succeeded:){constants.Colors.RESET}")
        else:
            print(f"{constants.Colors.client}action failed:(... {data}{constants.Colors.RESET}")

        # close the connection
        client_socket.close()
        print(f"{constants.Colors.client}----------------------------------------------------------------------------------"
              f"-\n{constants.Colors.RESET}")

    def send_message(self, msg_content, en_ip=constants.ROOT_CA_IP, en_port=constants.ROOT_CA_PORT):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((en_ip, en_port))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        action = 'verify_message'
        content = utils.cert2str(self.entity.certificate) + constants.SEP_STRING + msg_content + constants.SEP_STRING \
                  + (self.entity.signature(msg_content.encode())).hex()
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        # close the connection
        client_socket.close()
        print(f"{constants.Colors.client}----------------------------------------------------------------------------------"
              f"-\n{constants.Colors.RESET}")

    def revoke_my_cert(self, va_ip, va_port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((va_ip, va_port))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        action = 'revoke_cert'
        content = utils.cert2str(self.entity.certificate)
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        # close the connection
        client_socket.close()
        print(f"{constants.Colors.client}----------------------------------------------------------------------------------"
              f"-\n{constants.Colors.RESET}")

    # -----------------------------------server functions--------------------------------------

    def start_serv(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f"{constants.Colors.server}Setting up the server...{constants.Colors.RESET}")
        server_socket.bind((self.ip, self.port))
        server_socket.listen(5)
        print(f"{constants.Colors.server}Listening for clients...{constants.Colors.RESET}")

        while True:
            client, client_address = server_socket.accept()
            print(f"{constants.Colors.server}New client joined! {client_address}{constants.Colors.RESET}")
            start_new_thread(self.threaded_client, (client,))
            self.clients_thread_count += 1
            print(f"{constants.Colors.server}Thread Number:  {str(self.clients_thread_count)}{constants.Colors.RESET}")

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
                    print(f"{constants.Colors.server}finish issue_to_ca action{constants.Colors.RESET}")

                elif action == "verify_message":
                    cert_ver, mess_ver = self.verify_message(content)
                    if cert_ver == 0 and mess_ver == 0:
                        connection.send(b'No certificate found!')
                    elif cert_ver and mess_ver:
                        connection.send(b'verified certificate and message!')
                    elif cert_ver and not mess_ver:
                        connection.send(b'verified certificate and unverified message!')
                    elif not cert_ver and mess_ver:
                        connection.send(b'unverified certificate and verified message!')
                    else:
                        connection.send(b'unverified certificate and unverified message!')
                    print(f"{constants.Colors.server}finish verify_message action{constants.Colors.RESET}")

                elif action == "get_cert":
                    res = self.send_cert()
                    connection.send(res.encode())
                    print(f"{constants.Colors.server}finish send_cert action{constants.Colors.RESET}")

            else:
                print(f"{constants.Colors.server}Connection closed{constants.Colors.RESET}", )
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
        cert, sep_letter, msg_and_signature = content.partition(constants.SEP_STRING)

        if cert == "None":
            return 0, 0

        cert = utils.str2cert(cert)

        msg, sep_string, signature = msg_and_signature.partition(constants.SEP_STRING)

        # get the certification and check it
        cert_ver = self.verify_cert(cert)

        # get the message and check it
        mess_ver = self.verify_msg_content(msg.encode(), cert, bytes.fromhex(signature))

        return cert_ver, mess_ver

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
        print(f"{constants.Colors.client}{data}{constants.Colors.RESET}")

        action = 'verify_cert'
        content = utils.cert2str(cert)
        message = action.encode() + b' ' + content.encode()

        entity_server_socket.send(message)

        data = entity_server_socket.recv(constants.MESSAGE_SIZE).decode()
        res = (data == "True")

        # close the connection
        entity_server_socket.close()
        print(f"{constants.Colors.client}------------------------------------------------------------------------------\n"
              f"{constants.Colors.RESET}")
        return res
