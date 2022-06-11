import constants
import entity
from entity_sockets import EntitySockets

if __name__ == '__main__':
    ROOT_CA = EntitySockets(entity.Entity(constants.ROOT_CA_DOMAIN, is_CA=True), constants.ROOT_CA_IP,
                            constants.ROOT_CA_PORT)
    ROOT_CA.start()
