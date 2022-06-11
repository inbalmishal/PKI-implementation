import constants
import entity
from entity_sockets import EntitySockets

if __name__ == '__main__':
    entity = EntitySockets(entity.Entity("client", is_CA=False), constants.EN1_IP, constants.EN1_PORT)
    entity.start()
