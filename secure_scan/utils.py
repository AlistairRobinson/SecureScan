import random
from os import urandom
from typing import List
from string import ascii_lowercase
from binascii import b2a_hex
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj

def get_mac() -> str:
    """ Returns a random hexadecimal string of length 12

    Args:
        i (int): The length of the string to return

    Returns:
        str: The random string generated
    """
    return b2a_hex(urandom(6)).decode('utf-8')

def get_key() -> _RSAobj:
    """ Returns a randomly generated RSA key of size 1024 bits

    Returns:
        _RSAobj: The key generated
    """
    return RSA.generate(1024, Random.new().read)

def get_ssid() -> str:
    """ Returns a randomly generated SSID name

    Returns:
        str: The SSID name generated
    """
    return ''.join(random.choice(ascii_lowercase) for i in range(8))

def fragment(l: List, n: int) -> List[List]:
    """ Fragments a list `l` into a list of lists, each of size `n`

    Args:
        l (List): The list to fragment
        n (int):  The size of each sublist

    Returns:
        List[List]: The fragmented list generated from `l`
    """
    return [l[i * n:(i + 1) * n] for i in range((len(l) + n - 1) // n)]
