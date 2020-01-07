from simulation.frames import Frame, FrameType
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.PublicKey import RSA
from typing import List
import os, binascii, json, random, time

def get_hex(i:int) -> str:
    return binascii.b2a_hex(os.urandom(i)).decode('utf-8')

def get_key() -> _RSAobj:
    return RSA.generate(1024, Random.new().read)

def fragment(l:List[bytes], n:int) -> List[List[bytes]]:
    return [l[i * n:(i + 1) * n] for i in range((len(l) + n - 1) // n)]

class AccessPoint:

    def send_beacon(self) -> Frame:
        return Frame(FrameType['Beacon'],
                     self.mac_addr, "*", self.key.publickey().exportKey())

    def send_probe_response(self, request:Frame) -> Frame:
        msg = [self.key.decrypt(i) for i in request.contents]
        p_text = bytes([b for s in msg for b in s])
        st_pk = RSA.importKey(p_text)
        message = bytes(json.dumps({
            "ssid": self.ssid,
            "signature": str(self.key.sign(SHA256.new(p_text).digest(), 32)[0])
        }), 'utf-8')
        c_text = [st_pk.encrypt(i, 32) for i in fragment(message, 80)]
        return Frame(FrameType['ProbeResponse'],
                     self.mac_addr, "*", c_text)

    def __init__(self, ssid:str):
        self.mac_addr = get_hex(6)
        self.ssid = ssid
        self.key = get_key()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def __str__(self):
        return "Access Point: \t" + self.ssid + "\n" \
        "Global MAC address: \t" + self.mac_addr + "\n" \
        "Public key: \n" + self.key.publickey().exportKey().decode('utf-8') + "\n" \
        "Private key: \n" + self.key.exportKey().decode('utf-8')

class Station:

    def refresh(self):
        self.rmac_addr = get_hex(6)
        self.key = get_key()
        assert self.key.can_encrypt()
        assert self.key.has_private()
        assert self.key.can_sign()

    def send_probe_request(self, beacon:Frame) -> Frame:
        if beacon.source in self.memory:
            return None
        time.sleep(random.randint(1, 100) / 1000)
        self.refresh()
        ap_pk = RSA.importKey(beacon.contents)
        self.memory[beacon.source] = {
            'ap_pk': ap_pk,
            'st_sk': self.key,
            'time': time.time()
        }
        msg = self.key.publickey().exportKey()
        p_text = fragment(msg, 80)
        c_text = [ap_pk.encrypt(i, 32) for i in p_text]
        return Frame(FrameType['ProbeRequest'],
                     self.rmac_addr, "*", c_text)

    def verify_probe_response(self, response:Frame) -> bool:
        if response.source not in self.memory:
            return False
        if time.time() - self.memory[response.source]['time'] > 1:
            return False
        ap_pk = self.memory[response.source]['ap_pk']
        st_sk = self.memory[response.source]['st_sk']
        self.memory.pop(response.source)
        msg = [st_sk.decrypt(i) for i in response.contents]
        p_text = json.loads(bytes([b for s in msg for b in s]).decode('utf-8'))
        signature = (int(p_text['signature']), None)
        challenge = SHA256.new(st_sk.publickey().exportKey()).digest()
        if (p_text['ssid'], ap_pk.exportKey()) not in self.saved:
            return False
        return ap_pk.verify(challenge, signature)

    def __init__(self):
        self.mac_addr = get_hex(6)
        self.memory = {}
        self.saved = set()
        self.refresh()

    def __str__(self):
        return "Station: \t\n" \
        "Global MAC address: \t" + self.mac_addr + "\n" \
        "Random MAC address: \t" + self.rmac_addr + "\n" \
        "Public key: \n" + self.key.publickey().exportKey().decode('utf-8') + "\n" \
        "Private key: \n" + self.key.exportKey().decode('utf-8')
