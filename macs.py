import hashlib


def sha1(msg: bytes) -> bytes:
    """
    Hashes `msg` using SHA1 hash algorithm.

    :param msg: the message to be hashed
    :return: SHA1 hash of the message
    """

    sha1 = hashlib.sha1()
    sha1.update(msg)
    return sha1.digest()


def mac_combined(msg: bytes, K: bytes, mac_size) -> bytes:
    """
    Computes the MAC over the `msg` using `K` as sha1(msg || mac_keeloq(msg, K))

    :param msg: the message to be MAC'ed over
    :param K: the key used for the mac_keeloq
    :param mac_size: the size of the final MAC (at most 4B)
    :return: the mac value
    """
    # Import the solution from Task 1b
    from code import mac_keeloq

    keeloq_mac = mac_keeloq(msg=msg, K=K, mac_size=mac_size)
    combined_mac = sha1(msg + keeloq_mac)
    return combined_mac