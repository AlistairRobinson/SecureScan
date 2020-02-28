import json
import time
import random
from typing import Callable
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from secure_scan.frames import Frame, FrameType
from secure_scan.utils import get_mac, get_key, get_ssid, fragment

class AccessPoint:
    """ Represents an Access Point (AP) in a WiFi network

    Attributes:
        get_addr (Callable): A function which returns an address (e.g. MAC)
        ssid (str):          The AP's SSID, or human readable identifier
        addr (str):          The AP's global MAC address for sending frames
        key (RsaKey):        The AP's key object for asymmetric encryption
        memory (Dict):       The AP's long term memory
        uid (int):           The AP's unique identifier in the simulation
    """

    def __init__(self, ssid: str = None, get_addr: Callable = get_mac):
        self.get_addr = get_addr()
        self.memory = {}
        self.key = get_key()
        self.ssid = ssid if ssid else get_ssid()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def send_beacon(self) -> Frame:
        """ Returns a SecureScan Beacon frame sent by the AP

        Returns:
            Frame: The SecureScan Beacon frame sent
        """
        return Frame(FrameType['Beacon'], self.get_addr, "*",
                     self.key.publickey().exportKey())

    def send_probe_response(self, request: Frame) -> Frame:
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
        return Frame(FrameType['ProbeResponse'], self.get_addr, "*", c_text)

    def __str__(self):
        return "Access Point: \t{}\n" \
        "Global MAC address: \t{}\n" \
        "Public key: \n{}\n" \
        "Private key: \n{}" \
        "".format(self.ssid, self.get_addr,
                  self.key.publickey().exportKey().decode('utf-8'),
                  self.key.exportKey().decode('utf-8'))

class Station:
    """ Represents a Station (STA) in a WiFi network

    Attributes:
        get_addr (Callable): A function which returns an address (e.g. MAC)
        addr (str):          The STA's global MAC address for sending frames
        r_addr (str):        The STA's random MAC address for sending frames
        key (RsaKey):        The STA's key object for asymmetric encryption
        memory (Dict):       The STA's long term memory
        timeout (int):       The time taken before ignoring repeated beacons
        maxsleep (int):      The maximum delay used to avoid fingerprinting
        saved (Set):         The set of all AP SSIDs and keys saved by the STA
        uid (int):           The STA's unique identifier in the simulation
    """

    def __init__(self, get_addr: Callable = get_mac, timeout: int = 1, maxsleep: int = 100):
        self.get_addr = get_addr
        self.addr = self.get_addr()
        self.r_addr = self.get_addr
        self.timeout = timeout
        self.maxsleep = maxsleep
        self.memory = {}
        self.saved = set()
        self.refresh()

    def refresh(self):
        """ Refreshes a STA's `r_addr` and `key` to new values
        """
        self.r_addr = self.get_addr()
        self.key = get_key()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def save_ap(self, ap: AccessPoint):
        self.saved.add((ap.ssid, ap.key.publickey().exportKey()))

    def save_ssid_pk(self, ssid: str, ap_pk: RsaKey):
        self.saved.add((ssid, ap_pk.exportKey()))

    def send_probe_request(self, beacon: Frame) -> Frame:
        """ Returns a SecureScan Probe Response frame given a Beacon

        Args:
            beacon (Frame): The SecureScan Beacon frame to respond to

        Returns:
            Frame: The SecureScan Probe Request frame sent in response
        """
        if beacon.source in self.memory:
            if time.time() - self.memory[beacon.source]['time'] < 1:
                return None
        time.sleep(random.randint(1, self.maxsleep) / 1000)
        self.refresh()
        ap_pk = RSA.importKey(beacon.contents)
        next_rmac = self.get_addr()
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
        return Frame(FrameType['ProbeRequest'], self.r_addr, "*", c_text)

    def verify_probe_response(self, response: Frame) -> bool:
        """ Determines a SecureScan Probe Response frame's validity

        Args:
            response (Frame): The SecureScan Probe Response to validate

        Returns:
            bool: True if the `response` was valid, False otherwise
        """
        if response.source not in self.memory:
            return False
        if time.time() - self.memory[response.source]['time'] > self.timeout:
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
        self.get_addr = next_rmac
        return True

    def __str__(self):
        return "Station: \t\n" \
        "Global MAC address: \t{}\n" \
        "Random MAC address: \t{}\n" \
        "Public key: \n{}\n" \
        "Private key: \n{}" \
        "".format(self.get_addr, self.r_addr,
                  self.key.publickey().exportKey().decode('utf-8'),
                  self.key.exportKey().decode('utf-8'))
