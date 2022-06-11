import socket

import constants
import entity
import utils


class EntityClient:
    def __init__(self, entity, ip, port):
        self.entity = entity
        self.ip = ip
        self.port = port

    def cli_start(self):
        while True:
            print("what do you want to do? (choose a number)")
            print("[1] - get a certificate from CA")
            print("[2] - send message to other entity")
            print("[3] - turn into CA")
            print("other - exit")
            res = input()
            if res == '1':
                self.issue_on_CA()
            elif res == '2':
                msg = input("enter your message to check: ")
                self.send_message(msg)
            elif res == '3':
                self.entity.is_CA = True
                self.issue_on_CA(entity)
            else:
                return

    def issue_on_CA(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((constants.SERVER_HOST_IP, constants.SERVER_PORT))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(data)

        action = 'issue_to_ca'
        content = self.entity.domain + ' ' + utils.pub_key2str(self.entity.public_key) + ' ' + str(self.entity.is_CA)
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        if utils.is_cert_type(data):
            self.entity.certificate = utils.str2cert(data)
        else:
            print(data)

        # close the connection
        client_socket.close()
        print('------------------------------------------------------------------------------\n')

    def send_message(self, msg_content):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((constants.SERVER_HOST_IP, constants.SERVER_PORT))
        data = client_socket.recv(constants.MESSAGE_SIZE).decode()
        print(data)

        action = 'verify_message'
        content = utils.cert2str(self.entity.certificate) + msg_content + '***' + str(
            self.entity.signature(msg_content))
        message = action.encode() + b' ' + content.encode()

        client_socket.send(message)

        data = client_socket.recv(constants.MESSAGE_SIZE).decode()

        print(data)

        # close the connection
        client_socket.close()
        print('------------------------------------------------------------------------------\n')


if __name__ == '__main__':
    e = EntityClient(entity.Entity("client", is_CA=False), constants.CLIENT_IP, constants.CLIENT_PORT)
    e.cli_start()
