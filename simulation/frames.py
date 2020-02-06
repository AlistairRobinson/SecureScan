from datetime import datetime
from enum import Enum

class FrameType(Enum):
    Beacon = 1
    ProbeRequest = 2
    ProbeResponse = 3

class Frame:

    def __init__(self, t:FrameType, src:str, dest:str, uid:int, data):
        self.sent_at = datetime.now()
        self.type = t
        self.source = src
        self.destination = dest
        self.uid = uid
        self.contents = data

    def __str__(self):
        return "Data frame: \t{}\n" \
        "Sent at: \t{}\n" \
        "Source: \t{}\n" \
        "Destination: \t{}\n" \
        "Sent by actor {}\n" \
        "Contents: \n{}".format(self.type, self.sent_at,
        self.source, self.destination, self.uid, self.contents)
