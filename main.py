from entity import Entity
from ca import CA
from ra import RA
from va import VA

if __name__ == '__main__':
    va = VA()
    ra = RA()
    root_ca = CA(ra)
    other_ca = CA(ra)

    e1 = Entity(ra)
    e2 = Entity(ra)

    root_ca.issue_entity(e1, "e1", e1.public_key, "inbal", is_CA=False)
    other_ca.issue_entity(e2, "e2", e2.public_key, "alon", is_CA=False)

    msg = b"hello"
    msg_sign = e1.signature(msg)
    print(va.verify_cert(root_ca, e1))
    print(e2.verify_message(msg, e1, msg_sign))


