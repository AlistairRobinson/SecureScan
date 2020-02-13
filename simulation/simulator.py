import random
from typing import List
import progressbar as pb
from simulation.actors import Station, AccessPoint
from simulation.frames import Frame

def get_stations(s: int) -> List[Station]:
    """ Returns a list of `s` Stations objects

    Args:
        s (int): The number of stations to construct

    Returns:
        List[Station]: The list of newly constructed stations
    """
    return [Station(i) for i in pb.progressbar(range(s), term_width=100)]

def get_access_points(a: int) -> List[AccessPoint]:
    """ Returns a list of `a` Access Points (APs)

    Args:
        a (int): The number of APs to construct

    Returns:
        List[Station]: The list of newly constructed APs
    """
    return [AccessPoint(i) for i in pb.progressbar(range(a), term_width=100)]

def simulate_standard(stations: List[Station], aps: List[AccessPoint],
                      history: List[Frame], v: bool = False) -> bool:
    """ Simulates the WiFi handshake protocol, recorded in `history`

    Args:
        stations (List[Station]): The stations in the network
        aps (List[AccessPoint]):  The APs in the network
        history (List[Frame]):    The network history to append to
        v (bool, optional):       Verbose mode, defaults to False

    Returns:
        bool: True if the handshake was successful, False otherwise
    """
    st = random.choice(stations)
    ap = random.choice(aps)
    valid = (ap.ssid in [i[0] for i in st.saved])
    beacon = ap.send_beacon()
    history.append(beacon)
    if v:
        print(beacon)
    request = st.send_probe_request(beacon)
    if valid:
        response = ap.send_probe_response(request)
        history.append(request)
        history.append(response)
        if v:
            print(request)
            print(response)
        return True
    assert request is None
    return False

def simulate_secure_scan(stations: List[Station], aps: List[AccessPoint],
                         history: List[Frame], v: bool = False) -> bool:
    """ Simulates the SecureScan protocol, recorded in `history`

    Args:
        stations (List[Station]): The stations in the network
        aps (List[AccessPoint]):  The APs in the network
        history (List[Frame]):    The network history to append to
        v (bool, optional):       Verbose mode, defaults to False

    Returns:
        bool: True if the handshake was successful, False otherwise
    """
    st = random.choice(stations)
    ap = random.choice(aps)
    valid = ((ap.ssid, ap.key.publickey().exportKey()) in st.saved)
    beacon = ap.send_secure_beacon()
    request = st.send_secure_probe_request(beacon)
    response = ap.send_secure_probe_response(request)
    assert st.verify_secure_probe_response(response) == valid
    history.append(beacon)
    history.append(request)
    history.append(response)
    if v:
        print(beacon)
        print(request)
        print(response)
    return True
