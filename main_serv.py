from Entity_server import EntityServer
from VA_server import VA
import entity
import constants

if __name__ == '__main__':
    is_CA = input("CA? [y/n]: ")
    is_CA = (is_CA == 'y')
    CA = EntityServer(entity.Entity(domain="inbal", is_CA=is_CA), constants.SERVER_HOST_IP, constants.SERVER_PORT)
    CA.start_serv()

