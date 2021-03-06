import json
import time
import random
from typing import Callable, Tuple
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
        connected (bool):    The status of the STA
    """

    def __init__(self, get_addr: Callable = get_mac,
                 timeout: int = 1, maxsleep: int = 100):
        self.get_addr = get_addr
        self.addr = self.get_addr()
        self.r_addr = self.get_addr
        self.timeout = timeout
        self.maxsleep = maxsleep
        self.memory = {}
        self.saved = set()
        self.connected = False
        self.refresh()

    def refresh(self):
        """ Refreshes a STA's `r_addr` and `key` to new values
        """
        print(self.get_addr)
        self.r_addr = self.get_addr()
        self.key = get_key()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def save_ap(self, ap: AccessPoint):
        """ Saves an Access Point to the station's memory

        Args:
            ap (AccessPoint): The AccessPoint to save
        """
        self.saved.add((ap.ssid, ap.key.publickey().exportKey()))

    def save_ssid_pk(self, ssid: str, ap_pk: RsaKey):
        """ Saves an SSID/public key pair to the station's memory

        Args:
            ssid (str):     The SSID to save
            ap_pk (RsaKey): The public key associated with the ssid
        """
        self.saved.add((ssid, ap_pk.exportKey()))

    def clear_memory(self):
        """ Clears a Station's short term connection memory
        """
        self.memory = {}

    def clear_saved(self):
        """ Clears a Station's long term saved AP list
        """
        self.saved = set()

    def send_probe_request(self, beacon: Frame) -> Frame:
        """ Returns a SecureScan Probe Response frame given a Beacon

        Args:
            beacon (Frame): The SecureScan Beacon frame to respond to

        Raises:
            ValueError: If the AP sent a beacon before timeout

        Returns:
            Frame: The SecureScan Probe Request frame sent in response
        """
        if beacon.source in self.memory:
            if time.time() - self.memory[beacon.source]['time'] < self.timeout:
                raise ValueError("Beacon already received before timeout")
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

    def verify_probe_response(self, response: Frame) -> Tuple[bool, str, RsaKey]:
        """ Determines a SecureScan Probe Response frame's validity

        Args:
            response (Frame): The SecureScan Probe Response to validate

        Raises:
            ValueError: If the `response` is invalid

        Returns:
            bool:   True if the handshake was successful, False otherwise
            str:    The SSID of the AP
            RsaKey: The public key of the AP
        """
        if response.source not in self.memory:
            raise ValueError("Probe Response source not in memory")
        if time.time() - self.memory[response.source]['time'] > self.timeout:
            raise ValueError("Probe Response timed out")
        ap_pk = self.memory[response.source]['ap_pk']
        st_sk = self.memory[response.source]['st_sk']
        next_rmac = self.memory[response.source]['next_rmac']
        self.memory.pop(response.source)
        msg = [PKCS1_OAEP.new(st_sk).decrypt(i) for i in response.contents]
        p_text = json.loads(bytes([b for s in msg for b in s]).decode('utf-8'))
        signature = bytes.fromhex(p_text['signature'])
        challenge = SHA256.new(st_sk.publickey().exportKey())
        if (p_text['ssid'], ap_pk.exportKey()) not in self.saved:
            return False, p_text['ssid'], ap_pk
        pkcs1_15.new(ap_pk).verify(challenge, signature)
        self.r_mac = next_rmac
        self.connected = True
        return True, p_text['ssid'], ap_pk

    def __str__(self):
        return "Station: \t\n" \
        "Global MAC address: \t{}\n" \
        "Random MAC address: \t{}\n" \
        "Public key: \n{}\n" \
        "Private key: \n{}" \
        "".format(self.get_addr, self.r_addr,
                  self.key.publickey().exportKey().decode('utf-8'),
                  self.key.exportKey().decode('utf-8'))
