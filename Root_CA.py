from datetime import datetime
import constants
import entity
from certificate import Certificate
from entity_sockets import EntitySockets

if __name__ == '__main__':
    e = entity.Entity(constants.ROOT_CA_DOMAIN, is_CA=True)
    e.certificate = Certificate(constants.ROOT_CA_DOMAIN, e.public_key, constants.ROOT_CA_DOMAIN,
                                constants.ROOT_CA_DOMAIN, constants.ROOT_CA_IP, constants.ROOT_CA_PORT, True,
                                datetime.date(datetime.now()))
    ROOT_CA = EntitySockets(e, constants.ROOT_CA_IP,
                            constants.ROOT_CA_PORT)
    ROOT_CA.start()
