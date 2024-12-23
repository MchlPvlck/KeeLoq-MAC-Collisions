def XOR(array1: bytes, array2: bytes) -> bytes:
    r"""
    XORs byte-by-byte the input arrays. The returned value
    has the length of the shorter input.

    :param array1:
    :param array2:
    :return: XOR of the two byte arrays

    >>> import random
    >>> size = random.randint(1, 32)
    >>> array = random.randbytes(size)
    >>> XOR(array, array) == b"\x00" * size
    True
    """
    return bytes([a ^ b for a, b in zip(array1, array2)])


def bytes2int(array: bytes) -> int:
    r"""
    Converts the `array` to an integer using big-endian.

    >>> bytes2int(b'\x01\x02\x03\x04')
    16909060
    >>> bytes2int(b'\xff\xff\xff\xff')
    4294967295
    """
    return int.from_bytes(array, byteorder="big", signed=False)


def int2bytes(integer: int) -> bytes:
    r"""
    Converts the `integer` from the range [0, 2^32 - 1] to four bytes using big-endian.

    >>> int2bytes(0x01020304)
    b'\x01\x02\x03\x04'
    >>> int2bytes(0x00)
    b'\x00\x00\x00\x00'
    >>> int2bytes(2**32 - 1)
    b'\xff\xff\xff\xff'
    """

    return integer.to_bytes(byteorder="big", length=4, signed=False)