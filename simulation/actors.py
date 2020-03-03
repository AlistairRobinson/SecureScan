import json
import time
import random
from binascii import b2a_hex
from os import urandom
from string import ascii_lowercase
from typing import List
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from simulation.frames import Frame, FrameType

def get_hex(i: int) -> str:
    """ Returns a random hexadecimal string of length `i`

    Args:
        i (int): The length of the string to return

    Returns:
        str: The random string generated
    """
    return b2a_hex(urandom(i//2)).decode('utf-8')

def get_key() -> RsaKey:
    """ Returns a randomly generated RSA key of size 1024 bits

    Returns:
        RsaKey: The key generated
    """
    return RSA.generate(1024)

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

class AccessPoint:
    """ Represents an Access Point (AP) in a WiFi network

    Attributes:
        ssid (str):     The AP's SSID, or human readable identifier
        mac_addr (str): The AP's global MAC address for sending data frames
        key (RsaKey):   The AP's key object for asymmetric encryption
        memory (Dict):  The AP's long term memory
        uid (int):      The AP's unique identifier in the simulation
    """

    def send_beacon(self) -> Frame:
        """ Returns a WiFi Beacon frame sent by the AP

        Returns:
            Frame: The WiFi Beacon frame sent
        """
        return Frame(FrameType['Beacon'], self.mac_addr,
                     "*", self.uid, self.ssid)

    def send_secure_beacon(self) -> Frame:
        """ Returns a SecureScan Beacon frame sent by the AP

        Returns:
            Frame: The SecureScan Beacon frame sent
        """
        return Frame(FrameType['Beacon'], self.mac_addr,
                     "*", self.uid, self.key.publickey().exportKey())

    def send_probe_response(self, request: Frame) -> Frame:
        """ Returns a WiFi Probe Response frame given a Probe Request

        Args:
            request (Frame): The WiFi Probe Request to respond to

        Returns:
            Frame: The WiFi Probe Response frame sent in response
            None:  If the AP does not wish to respond to the `request`
        """
        if request.contents == self.ssid or request.contents == "*":
            return Frame(FrameType['ProbeResponse'], self.mac_addr,
                         request.source, self.uid, self.ssid)
        return None

    def send_secure_probe_response(self, request: Frame) -> Frame:
        """ Returns a SecureScan Probe Response frame given a Probe Request

        Args:
            request (Frame): The SecureScan Probe Request to respond to

        Returns:
            Frame: The SecureScan Probe Response frame sent in response
        """
        msg = [PKCS1_OAEP.new(self.key).decrypt(i) for i in request.contents]
        p_text = json.loads(bytes([b for s in msg for b in s]).decode('utf-8'))
        st_pk_exp = p_text['st_pk'][2:-1].replace('\\n', '\n').encode('utf-8')
        st_pk = RSA.importKey(st_pk_exp)
        self.memory[p_text['next_rmac']] = time.time()
        s = pkcs1_15.new(self.key).sign(SHA256.new(st_pk_exp))
        m = bytes(json.dumps({
            "ssid": self.ssid,
            "signature": s.hex()
        }), 'utf-8')
        c_text = [PKCS1_OAEP.new(st_pk).encrypt(i) for i in fragment(m, 80)]
        return Frame(FrameType['ProbeResponse'], self.mac_addr,
                     "*", self.uid, c_text)

    def __init__(self, uid: int, ssid: str = None):
        self.mac_addr = get_hex(12)
        self.memory = {}
        self.uid = uid
        self.key = get_key()
        self.ssid = ssid if ssid else get_ssid()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def __str__(self):
        return "Access Point: \t{}\n" \
        "Global MAC address: \t{}\n" \
        "Public key: \n{}\n" \
        "Private key: \n{}" \
        "".format(self.ssid, self.mac_addr,
                  self.key.publickey().exportKey().decode('utf-8'),
                  self.key.exportKey().decode('utf-8'))

class Station:
    """ Represents a Station (STA) in a WiFi network

    Attributes:
        mac_addr (str):  The STA's global MAC address for sending data frames
        rmac_addr (str): The STA's random MAC address for sending data frames
        key (RsaKey):   The STA's key object for asymmetric encryption
        memory (Dict):   The STA's long term memory
        saved (Set):     The set of all AP SSIDs and keys saved by the STA
        uid (int):       The STA's unique identifier in the simulation
    """

    def refresh(self):
        """ Refreshes a STA's `rmac_addr` and `key` to new values
        """
        self.rmac_addr = get_hex(12)
        self.key = get_key()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def send_probe_request(self, beacon: Frame) -> Frame:
        """ Returns a WiFi Probe Response frame given a Beacon

        Args:
            beacon (Frame): The WiFi Beacon frame to respond to

        Returns:
            Frame: The WiFi Probe Request frame sent in response
            None:  If the STA does not wish to respond to the `beacon`
        """
        self.rmac_addr = get_hex(12)
        if beacon.contents in [i[0] for i in self.saved]:
            return Frame(FrameType['ProbeRequest'], self.rmac_addr,
                         "*", self.uid, beacon.contents)
        return None

    def send_secure_probe_request(self, beacon: Frame) -> Frame:
        """ Returns a SecureScan Probe Response frame given a Beacon

        Args:
            beacon (Frame): The SecureScan Beacon frame to respond to

        Returns:
            Frame: The SecureScan Probe Request frame sent in response
        """
        if beacon.source in self.memory:
            if time.time() - self.memory[beacon.source]['time'] < 1:
                return None
        time.sleep(random.randint(1, 100) / 1000)
        self.refresh()
        ap_pk = RSA.importKey(beacon.contents)
        next_rmac = get_hex(12)
        self.memory[beacon.source] = {
            'ap_pk': ap_pk,
            'st_sk': self.key,
            'time': time.time(),
            'next_rmac': next_rmac
        }
        msg = bytes(json.dumps({
            "st_pk": str(self.key.publickey().exportKey()),
            "next_rmac": next_rmac
        }), 'utf-8')
        p_text = fragment(msg, 80)
        c_text = [PKCS1_OAEP.new(ap_pk).encrypt(i) for i in p_text]
        return Frame(FrameType['ProbeRequest'], self.rmac_addr,
                     "*", self.uid, c_text)

    def verify_secure_probe_response(self, response: Frame) -> bool:
        """ Determines a SecureScan Probe Response frame's validity

        Args:
            response (Frame): The SecureScan Probe Response to validate

        Returns:
            bool: True if the `response` was valid, False otherwise
        """
        if response.source not in self.memory:
            return False
        if time.time() - self.memory[response.source]['time'] > 1:
            return False
        ap_pk = self.memory[response.source]['ap_pk']
        st_sk = self.memory[response.source]['st_sk']
        next_rmac = self.memory[response.source]['next_rmac']
        self.memory.pop(response.source)
        msg = [PKCS1_OAEP.new(st_sk).decrypt(i) for i in response.contents]
        p_text = json.loads(bytes([b for s in msg for b in s]).decode('utf-8'))
        signature = bytes.fromhex(p_text['signature'])
        challenge = SHA256.new(st_sk.publickey().exportKey())
        if (p_text['ssid'], ap_pk.exportKey()) not in self.saved:
            return False
        try:
            pkcs1_15.new(ap_pk).verify(challenge, signature)
        except ValueError:
            return False
        self.mac_addr = next_rmac
        return True

    def __init__(self, uid: int):
        self.uid = uid
        self.mac_addr = get_hex(12)
        self.rmac_addr = self.mac_addr
        self.memory = {}
        self.saved = set()
        self.refresh()

    def __str__(self):
        return "Station: \t\n" \
        "Global MAC address: \t{}\n" \
        "Random MAC address: \t{}\n" \
        "Public key: \n{}\n" \
        "Private key: \n{}" \
        "".format(self.mac_addr, self.rmac_addr,
                  self.key.publickey().exportKey().decode('utf-8'),
                  self.key.exportKey().decode('utf-8'))
