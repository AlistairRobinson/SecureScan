from datetime import datetime
from enum import Enum

class FrameType(Enum):
    Beacon = 1
    ProbeRequest = 2
    ProbeResponse = 3

class Frame:

    def __init__(self, t:FrameType, src:str, dest:str, data):
        self.sent_at = datetime.now()
        self.type = t
        self.source = src
        self.destination = dest
        self.contents = data

    def __str__(self):
        return "Data frame: \t" + str(self.type) + "\n" \
        "Sent at: \t" + str(self.sent_at) + "\n" \
        "Source: \t" + self.source + "\n" \
        "Destination: \t" + self.destination + "\n" \
        "Contents: \n" + str(self.contents)
