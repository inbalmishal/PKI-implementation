from entity import Entity
from certificate_authority import CA
from validation_authority import VA

if __name__ == '__main__':
    # initialization
    root_ca = CA("root_CA")
    va = VA(root_ca)

    # create some CA-s
    good_ca = CA("good_CA")
    root_ca.issue_entity(good_ca, good_ca.public_key, signer_name="good_CA", is_CA=True)

    good_ca2 = CA("good_CA2")
    good_ca.issue_entity(good_ca2, good_ca2.public_key, signer_name="good_CA2", is_CA=True)

    bad_ca = CA("bad_CA")
    bad_ca2 = CA("bad_CA2")
    bad_ca.issue_entity(bad_ca2, bad_ca2.public_key, signer_name="bad_CA2", is_CA=True)

    # create some entities and issue them
    e_root = Entity("entity_root")
    root_ca.issue_entity(e_root, e_root.public_key, signer_name="e_root", is_CA=False)
    e_good = Entity("entity_good")
    good_ca.issue_entity(e_good, e_good.public_key, signer_name="e_good", is_CA=False)
    e_good2 = Entity("entity_good2")
    good_ca2.issue_entity(e_good2, e_good2.public_key, signer_name="e_good2", is_CA=False)
    e_bad = Entity("entity_bad")
    bad_ca.issue_entity(e_bad, e_bad.public_key, signer_name="e_bad", is_CA=False)
    e_bad2 = Entity("entity_bad2")
    bad_ca2.issue_entity(e_bad2, e_bad2.public_key, signer_name="e_bad2", is_CA=False)


    # check the certificates
    print('-----------------------------------------------------------------------------------------------------')
    print('------------------------------------ certification verification -------------------------------------')
    print('-----------------------------------------------------------------------------------------------------')
    print("e_root cert verification result: ", va.verify_cert(e_root.certificate))
    print("e_good cert verification result: ", va.verify_cert(e_good.certificate))
    print("e_good2 cert verification result: ", va.verify_cert(e_good2.certificate))
    print("e_bad cert verification result: ", va.verify_cert(e_bad.certificate))
    print("e_bad2 cert verification result: ", va.verify_cert(e_bad2.certificate))

    # verify the messages (without checking the certificate)
    print('-----------------------------------------------------------------------------------------------------')
    print('--------------------------------------- message verification ----------------------------------------')
    print('-----------------------------------------------------------------------------------------------------')
    msg1 = b"good!"
    msg2 = b"bad!"
    e_good_msg_signature = e_good.signature(msg1)
    print("good try result: ", e_good2.verify_message(msg1, e_good, e_good_msg_signature))
    print("bad try result: ", e_good2.verify_message(msg2, e_good, e_good_msg_signature))

    # check both
    print('-----------------------------------------------------------------------------------------------------')
    print('------------------------------ message and certification verification -------------------------------')
    print('-----------------------------------------------------------------------------------------------------')
    print("e_bad -> e_good result: ", e_good.check_all_message(va, msg1, e_bad))
    print("e_bad -> e_good2 result: ", e_good2.check_all_message(va, msg1, e_bad))
    print("e_good -> e_bad result: ", e_bad.check_all_message(va, msg1, e_good))


# validate the connection between the ca to the entity with encryption of pk with sk -> ?

# client-server application? NO:(

# if we change the key? -> revocation
# if the ca change the key? -> revocation
