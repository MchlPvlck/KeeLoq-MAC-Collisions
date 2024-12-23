"""
The implementation of the KeeLoq cipher. The `encrypt` and `decrypt` functions are taken
directly from the source: https://github.com/socram8888/leekoq
"""

import math
from typing import Final
import typing

from utils import int2bytes, bytes2int, XOR

LUT: Final[int] = 0x3A5C742E

KEELOQ_BYTE_BLOCK_SIZE: Final[int] = 4


def encrypt(block: int, key: int) -> int:
    """
    Encrypts a 32-bit block of plaintext using the KeeLoq algorithm.

    :param int block: 32-bit plaintext block
    :param int key: 64-bit key
    :return: 32-bit ciphertext block
    """

    for i in range(528):
        # Calculate LUT key
        lutkey = (block >> 1) & 1 | (block >> 8) & 2 | (block >> 18) & 4 | (block >> 23) & 8 | (block >> 27) & 16

        # Calculate next bit to feed
        msb = (block >> 16 & 1) ^ (block & 1) ^ (LUT >> lutkey & 1) ^ (key & 1)

        # Feed it
        block = msb << 31 | block >> 1

        # Rotate key right
        key = (key & 1) << 63 | key >> 1

    return block


def decrypt(block: int, key: int) -> int:
    """
    Decrypts a 32-bit block of ciphertext using the KeeLoq algorithm.

    :param int block: 32-bit ciphertext block
    :param int key: 64-bit key
    :return: 32-bit plaintext block

    >>> import random
    >>> import secrets
    >>> plaintext = int.from_bytes(random.randbytes(4), "big")
    >>> key = int.from_bytes(secrets.token_bytes(8), "big")
    >>> plaintext == decrypt(encrypt(plaintext, key), key)
    True
    """

    for i in range(528):
        # Calculate LUT key
        lutkey = (block >> 0) & 1 | (block >> 7) & 2 | (block >> 17) & 4 | (block >> 22) & 8 | (block >> 26) & 16

        # Calculate next bit to feed
        lsb = (block >> 31) ^ (block >> 15 & 1) ^ (LUT >> lutkey & 1) ^ (key >> 15 & 1)

        # Feed it
        block = (block & 0x7FFFFFFF) << 1 | lsb

        # Rotate key left
        key = (key & 0x7FFFFFFFFFFFFFFF) << 1 | key >> 63

    return block


def keeloq_enc(msg: bytes, K: bytes) -> bytes:
    """
    Encrypts the message `msg` with the key `K` in the ECB mode using the KeeLoq encryption function, see `encrypt` function.

    :param msg: plaintext (one block only = 32 bits)
    :param K: 8 bytes = 64 bits
    :return: ciphertext (one block only = 32 bits)
    """
    ctx_int = encrypt(block=bytes2int(msg), key=bytes2int(K))
    return int2bytes(ctx_int)


def keeloq_dec(ciphertext: bytes, K: bytes) -> bytes:
    """
    Decrypts the ciphertext `ciphertext` with the key `K` in the ECB mode using the KeeLoq decryption function, see `decrypt` function.

    :param ciphertext: ciphertext (one block only = 32 bits)
    :param K: 8 bytes = 64 bits
    :return: plaintext (one block only = 32 bits)

    >>> import random
    >>> import secrets
    >>> plaintext = random.randbytes(4)
    >>> key = secrets.token_bytes(8)
    >>> plaintext == keeloq_dec(keeloq_enc(plaintext, key), key)
    True
    """
    ptx_int = decrypt(block=bytes2int(ciphertext), key=bytes2int(K))
    return int2bytes(ptx_int)


def pkcs7_padding(msg_len: int, block_size: int) -> bytes:
    """
    Helper function to be used in the CBC mode to create the padding block.
    See RFC 5652 for description https://www.rfc-editor.org/rfc/rfc5652#section-6.3

    :param msg_len: length of the entire message, e.i., the number of bytes of `msg`
    :param block_size: length of block (in bytes) that uses corresponding block cipher (e.g. for AES block_size = 16 )
    :return: padding (block which should be appended to msg)
    """

    padding_size = block_size - (msg_len % block_size)
    padding = [padding_size] * padding_size
    return bytes(padding)


def pad(msg: bytes, block_size: int) -> bytes:
    """
    If msg has complete last block than one extra block is appended = padded message (in case of PKCS7) is always bigger than original msg
    :param msg:
    :param block_size: the block sizes in bytes
    :return: padded message = concatenation of original msg and PKCS7 padding
    """
    padding = pkcs7_padding(msg_len=len(msg), block_size=block_size)
    return msg + padding


def unpad(msg: bytes) -> bytes:
    """
    Strips the PKCS#7 padding from `msg`.

    :param msg: plaintext message
    :return: unpaded message

    >>> import random
    >>> message = random.randbytes(random.randint(1, 1024))
    >>> message == unpad(pad(message, 4))
    True
    """
    padding_size = msg[-1]
    assert 1 <= padding_size <= 4
    return msg[:-padding_size]


def keeloq_cbc_dec(ciphertext: bytes, IV: bytes, K: bytes) -> bytes:
    """
    Decrypts the ciphertext `ciphertext` using the key `K` and initialization vector `IV`
    using the CBC mode with the KeeLoq cipher.

    :param ciphertext: KeeLoq CBC ciphertext
    :param IV: the initialization vector 4 bytes
    :param K: the secret key 8 bytes
    :return: KeeLoq CBC plaintext
    """

    msg_padded = ciphertext
    num_blocks = len(ciphertext) // KEELOQ_BYTE_BLOCK_SIZE

    ctx_block_previous = IV
    res = bytes()
    for idx in range(num_blocks):
        ctx_block = msg_padded[idx * KEELOQ_BYTE_BLOCK_SIZE : (idx + 1) * KEELOQ_BYTE_BLOCK_SIZE]
        decrypted_block = keeloq_dec(ciphertext=ctx_block, K=K)
        ptx_block = XOR(decrypted_block, ctx_block_previous)
        ctx_block_previous = ctx_block
        res += ptx_block

    res = unpad(res)
    return res
