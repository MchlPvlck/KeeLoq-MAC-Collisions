#!/usr/bin/env python3
import hashlib
import os
from typing import Tuple

import keeloq
import utils
import macs


def keeloq_cbc_enc(msg: bytes, IV: bytes, K: bytes) -> bytes:
    """
    Encrypts the message `msg` using the key `K` and initialization vector `IV` using
    the KeeLoq cipher in the CBC mode.

    :param msg: arbitrary size
    :param IV: block size = 4B
    :param K: key size = 8B
    :return: Keeloq CBC ciphertext
    """
    # Task 1a
    # pad the message
    padded_message = keeloq.pad(msg, block_size=keeloq.KEELOQ_BYTE_BLOCK_SIZE)

    # initialize ciphertext and IV
    ciphertext = b""
    previous_cipher_block = IV

    # process each block in CBC mode
    for i in range(0, len(padded_message), keeloq.KEELOQ_BYTE_BLOCK_SIZE):
        current_block = padded_message[i:i + keeloq.KEELOQ_BYTE_BLOCK_SIZE]
        xor_block = utils.XOR(current_block, previous_cipher_block)
        cipher_block = keeloq.keeloq_enc(xor_block, K)
        ciphertext += cipher_block
        previous_cipher_block = cipher_block

    return ciphertext


def mac_keeloq(msg: bytes, K: bytes, mac_size: int = 4) -> bytes:
    """
    Computes vanilla CBC MAC, the last block of CBC encryption of `msg`.
    `mac_size` (bytes) allows shorter MACs than the size of the block

    :param msg: the message to be MAC'ed over
    :param K: the K that will be used for the KeeLoq cipher
    :param mac_size: the size of the final MAC (in bytes)
    :return: MAC of size mac_size
    """
    # Task 1b
    # check size
    if not (1 <= mac_size <= 4):
        raise ValueError("MAC size must be between 1 and 4 bytes.")


    # initialize IV, set the previous block to IV and pad
    IV = b"\x00\x00\x00\x00"
    padded_message = keeloq.pad(msg, keeloq.KEELOQ_BYTE_BLOCK_SIZE)
    total_blocks = len(padded_message) // keeloq.KEELOQ_BYTE_BLOCK_SIZE

    current_cipher_block = IV

    # process each block in CBC mode
    for i in range(total_blocks):
        # get current block and pad
        current_message_block = padded_message[i * keeloq.KEELOQ_BYTE_BLOCK_SIZE: (i + 1) * keeloq.KEELOQ_BYTE_BLOCK_SIZE]
        # XOR current block with previous ciphertext
        xor_block = utils.XOR(current_message_block, current_cipher_block)
        # encrypt with KeeLoq
        current_cipher_block = keeloq.keeloq_enc(xor_block, K)

    return current_cipher_block[-mac_size:]


def mac_keeloq_collision(K: bytes, mac_size) -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that form a collision under the `mac_keeloq` function.

    :param K: the K for the underlying KeeLoq cipher
    :param mac_size: the size in bytes of the final MAC
    :return: pair of distinct messages that have the same KeeLoq CBC-MAC
    """
    # Task 2a
    # dictionary to store observed MACs with their messages
    observed_macs = {}

    while True:
        # generate a random message
        random_message = os.urandom(8)

        # compute the MAC for message
        generated_mac = mac_keeloq(random_message, K, mac_size)

        # if mac has been seen
        if generated_mac in observed_macs:
            colliding_message = observed_macs[generated_mac]
            # verify that msg1 and msg2 are different
            if random_message != colliding_message:
                return random_message, colliding_message

        # store MAC and message if new
        observed_macs[generated_mac] = random_message


def sha1_collision(msg: bytes) -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `SHA1` function.
    Also `msg` appears as a substring in each of the messages.

    :param msg: `bytes` of the size less than 100
    :return: A tuple of two distinct messages that have the same SHA1 hash
             and contain `msg` as a substring.
    """
    bound = 100
    len_msg = len(msg)
    if len_msg > bound:
        raise ValueError(f"The length of `msg` is {len_msg}, which is greater than {bound}")

    # Task 2b
    # two copied collision prefixes that make basis for this attack
    collision_prefix1 = bytes.fromhex(
        "255044462D312E330A25E2E3CFD30A0A0A312030206F626A0A3C3C2F57696474682032203020522F4865696768742033203020522F547970652034203020522F537562747970652035203020522F46696C7465722036203020522F436F6C6F7253706163652037203020522F4C656E6774682038203020522F42697473506572436F6D706F6E656E7420383E3E0A73747265616D0AFFD8FFFE00245348412D3120697320646561642121212121852FEC092339759C39B1A1C63C4C97E1FFFE017346DC9166B67E118F029AB621B2560FF9CA67CCA8C7F85BA84C79030C2B3DE218F86DB3A90901D5DF45C14F26FEDFB3DC38E96AC22FE7BD728F0E45BCE046D23C570FEB141398BB552EF5A0A82BE331FEA48037B8B5D71F0E332EDF93AC3500EB4DDC0DECC1A864790C782C76215660DD309791D06BD0AF3F98CDA4BC4629B1"
    )
    collision_prefix2 = bytes.fromhex(
        "255044462D312E330A25E2E3CFD30A0A0A312030206F626A0A3C3C2F57696474682032203020522F4865696768742033203020522F547970652034203020522F537562747970652035203020522F46696C7465722036203020522F436F6C6F7253706163652037203020522F4C656E6774682038203020522F42697473506572436F6D706F6E656E7420383E3E0A73747265616D0AFFD8FFFE00245348412D3120697320646561642121212121852FEC092339759C39B1A1C63C4C97E1FFFE017F46DC93A6B67E013B029AAA1DB2560B45CA67D688C7F84B8C4C791FE02B3DF614F86DB1690901C56B45C1530AFEDFB76038E972722FE7AD728F0E4904E046C230570FE9D41398ABE12EF5BC942BE33542A4802D98B5D70F2A332EC37FAC3514E74DDC0F2CC1A874CD0C78305A21566461309789606BD0BF3F98CDA8044629A1"
    )

    # add message to prefixes
    modified_message1 = collision_prefix1 + msg
    modified_message2 = collision_prefix2 + msg

    # compute hashes

    hash1 = macs.sha1(modified_message1)
    hash2 = macs.sha1(modified_message2)

    # print results
    print("Message 1:", modified_message1)
    print("SHA-1 Hash of Message 1:", hash1)
    print("\nMessage 2:", modified_message2)
    print("SHA-1 Hash of Message 2:", hash2)

    # verify same hashes
    assert hash1 == hash2, "The SHA-1 hash of msg1 and msg2 do not match. Collision failed."

    # ensure messages are under 600 bytes
    assert len(modified_message1) < 600 and len(modified_message2) < 600, "Message length exceeds 600 bytes"

    if hash1 == hash2:print("SHA1 collision was successful!!!")

    return modified_message1, modified_message2







def mac_combined_collision(msg: bytes, mac_size: int = 4) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Generates a tuple (msg1, key1, msg2, key2) that forms a collision under the `mac_combined`
    function. That means that for the aformentioned tuple it holds that:

     - msg1 != msg2, and
     - sha1(msg1 || mac_keeloq(msg1, key1)) == sha1(msg2 || mac_keeloq(msg2, key2)), and
     - msg appears as a substring in both of the messages msg1 and msg2.


    :return: a tuple (msg1, key1, msg2, key2)
    """
    # check lenght
    bound = 100
    len_msg = len(msg)
    if len_msg > bound:
        raise ValueError(f"The length of `msg` is {len_msg}, which is greater than {bound}")
    # two copied collision prefixes that make basis for this attack
    collision_prefix1 = bytes.fromhex(
        "255044462D312E330A25E2E3CFD30A0A0A312030206F626A0A3C3C2F57696474682032203020522F4865696768742033203020522F547970652034203020522F537562747970652035203020522F46696C7465722036203020522F436F6C6F7253706163652037203020522F4C656E6774682038203020522F42697473506572436F6D706F6E656E7420383E3E0A73747265616D0AFFD8FFFE00245348412D3120697320646561642121212121852FEC092339759C39B1A1C63C4C97E1FFFE017346DC9166B67E118F029AB621B2560FF9CA67CCA8C7F85BA84C79030C2B3DE218F86DB3A90901D5DF45C14F26FEDFB3DC38E96AC22FE7BD728F0E45BCE046D23C570FEB141398BB552EF5A0A82BE331FEA48037B8B5D71F0E332EDF93AC3500EB4DDC0DECC1A864790C782C76215660DD309791D06BD0AF3F98CDA4BC4629B1"
    )
    collision_prefix2 = bytes.fromhex(
        "255044462D312E330A25E2E3CFD30A0A0A312030206F626A0A3C3C2F57696474682032203020522F4865696768742033203020522F547970652034203020522F537562747970652035203020522F46696C7465722036203020522F436F6C6F7253706163652037203020522F4C656E6774682038203020522F42697473506572436F6D706F6E656E7420383E3E0A73747265616D0AFFD8FFFE00245348412D3120697320646561642121212121852FEC092339759C39B1A1C63C4C97E1FFFE017F46DC93A6B67E013B029AAA1DB2560B45CA67D688C7F84B8C4C791FE02B3DF614F86DB1690901C56B45C1530AFEDFB76038E972722FE7AD728F0E4904E046C230570FE9D41398ABE12EF5BC942BE33542A4802D98B5D70F2A332EC37FAC3514E74DDC0F2CC1A874CD0C78305A21566461309789606BD0BF3F98CDA8044629A1"
    )
    # add message to prefixes
    message1 = collision_prefix1 + msg
    message2 = collision_prefix2 + msg

    # dictionary to store observed keys with their messages
    keys_stored = {}

    while True:
        # generate a random key
        random_key = secrets.token_bytes(8)

        # compute KeeLoq MAC
        mac1 = mac_keeloq(message1, random_key, mac_size)

        # check if there is collision
        if mac1 in keys_stored:
            previous_key, previous_message = keys_stored[mac1]
            if previous_message == message1:
                # skip if previous message was `msg2`
                continue

            # if both SHA-1 hashes match for same combined MAC
            combined1 = macs.sha1(message1 + mac1)
            combined2 = macs.sha1(previous_message + mac1)

            if combined1 == combined2:
                print("Collision found!")
                return message1, random_key, previous_message, previous_key
        else:
            # no collision, store the MAC1 and key
            keys_stored[mac1] = (random_key, message1)

        # store for msg2 to increase collision rate
        mac2 = mac_keeloq(message2, random_key, mac_size)
        if mac2 in keys_stored:
            previous_key, previous_message = keys_stored[mac2]
            if previous_message == message2:
                # skip if previous message was `msg2`
                continue

            # if both SHA-1 hashes match for same combined MAC
            combined1 = hashlib.sha1(message2 + mac2).digest()
            combined2 = hashlib.sha1(previous_message + mac2).digest()

            if combined1 == combined2:
                print("Collision found!")
                return message2, random_key, previous_message, previous_key
        else:
            # no collision, store the MAC2 and key
            keys_stored[mac2] = (random_key, message2)


def test_mac_combined_collision(msg: bytes):
    # test mac_combined function
    mac_size = 3

    result = mac_combined_collision(msg, mac_size)
    if result:
        msg1, key1, msg2, key2 = result
        mac1 = macs.mac_combined(msg1, key1, mac_size)
        mac2 = macs.mac_combined(msg2, key2, mac_size)

        assert mac1 == mac2, "Collision failed: mac_combined outputs do not match."
        assert msg1 != msg2, "Message is not the same."
        # print details of the collision
        print("Test passed. Collision verified.")
        print("\n--- Collision Details ---")
        print("Message 1:", msg1)
        print("Key 1:", key1)
        print("MAC 1:", mac1)
        print("\nMessage 2:", msg2)
        print("Key 2:", key2)
        print("MAC 2:", mac2)
        print("\nVerification: MACs COMBINED are identical:", mac1 == mac2)
    else:
        print("Collision could not be found.")

def test_mac_keeloq_collision():
    # Measure how long does it take to find collisions against mac_keeloq
    key = secrets.token_bytes(8)
    print(f"Key: {key.hex(sep=' ')}")
    for mac_size in range(1, 5):
        print(f"MAC size: {mac_size}")
        start = time.time()
        print(mac_keeloq_collision(key, mac_size))
        duration = time.time() - start
        print(f"Finding a collisions against MAC KeeLoq took {duration} seconds")

def test_cbc_enc():
    # Test that CBC mode with KeeLoq is implemented correctly.
    with open("keeloq_cbc_test_vectors.json", "r") as handle:
        test_vectors = json.load(handle)
    for i, tv in enumerate(test_vectors):
        message = bytes.fromhex(tv["message"])
        key = bytes.fromhex(tv["key"])
        iv = bytes.fromhex(tv["iv"])
        expected_ciphertext = bytes.fromhex(tv["ciphertext"])

        result_ciphertext = keeloq_cbc_enc(message, iv, key)

        # Check if the result matches the expected ciphertext
        if result_ciphertext == expected_ciphertext:
            print(f"Test {i + 1} passed.")
        else:
            print(f"Test {i + 1} failed.")
            print(f"Expected: {expected_ciphertext.hex()}")
            print(f"Got:      {result_ciphertext.hex()}")


def test_mac_keeloq():
    # Test that MAC based on CBC KeeLoq is implemented correctly.
    with open("mac_keeloq_test_vectors.json", "r") as handle:
        test_vectors = json.load(handle)

    for i, tv in enumerate(test_vectors):
        message = bytes.fromhex(tv["message"])
        key = bytes.fromhex(tv["key"])
        mac_size = tv["mac_size"]
        mac = bytes.fromhex(tv["mac"])

        result_mac = mac_keeloq(message, key, mac_size)

        if result_mac == mac:
            print(f"Test Vector {i + 1} Passed")
        else:
            print(f"Test Vector {i + 1} Failed:")
            print(f"Expected MAC: {mac.hex()}")
            print(f"Got MAC:      {result_mac.hex()}")


if __name__ == "__main__":
    import json
    import secrets
    import time
    # test cbc enc function
    test_cbc_enc()
    # test cbc enc function
    test_mac_keeloq()

    test_msg = b"test message"
    # test mac collision function
    test_mac_keeloq_collision()
    # test sha1 collision function
    sha1_collision(test_msg)
    # test mac combined function
    test_mac_combined_collision(test_msg)

