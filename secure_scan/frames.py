from datetime import datetime
from enum import Enum

class FrameType(Enum):
    """ Represents the enumerable types of a frame in the network
    """
    Beacon = 1
    ProbeRequest = 2
    ProbeResponse = 3

class Frame:
    """ Represents a Frame in a WiFi network

    Attributes:
        sent_at (datetime): The time at which the Frame was sent
        type (FrameType):   The Frame's type (see FrameType)
        source (str):       The Frame's source MAC address
        destination (str):  The Frame's destination MAC address
        contents:           The Frame's contents or payload
    """

    def __init__(self, t: FrameType, src: str, dest: str, data):
        self.sent_at = datetime.now()
        self.type = t
        self.source = src
        self.destination = dest
        self.contents = data

    def __str__(self):
        return "Data frame: \t{}\n" \
        "Sent at: \t{}\n" \
        "Source: \t{}\n" \
        "Destination: \t{}\n" \
        "Contents: \n{}".format(self.type, self.sent_at, self.source,
                                self.destination, self.contents)
