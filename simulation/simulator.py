from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from typing import List
import progressbar as pb
import random

def get_stations(s:int) -> List[Station]:
    return [Station(i) for i in pb.progressbar(range(s), term_width=100)]

def get_access_points(a:int) -> List[AccessPoint]:
    return [AccessPoint(i) for i in pb.progressbar(range(a), term_width=100)]

def simulate_secure_scan(stations:List[Station], aps:List[AccessPoint], history:List[Frame], v:bool=False) -> bool:
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

def simulate_standard(stations:List[Station], aps:List[AccessPoint], history:List[Frame], v:bool=False) -> bool:
    st = random.choice(stations)
    ap = random.choice(aps)
    valid = (ap.ssid in [i[0] for i in st.saved])
    beacon = ap.send_beacon()
    history.append(beacon)
    if v:
        print(beacon)
    request = st.send_probe_request(beacon)
    if not valid:
        assert request is None
        return False
    else:
        response = ap.send_probe_response(request)
        history.append(request)
        history.append(response)
        if v:
            print(request)
            print(response)
        return True