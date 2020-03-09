import pytest, time
from secure_scan.actors import Station, AccessPoint

def test_station_constructor():
    a = Station()
    b = Station()
    assert a != b

def test_ap_constructor():
    a = AccessPoint()
    b = AccessPoint()
    assert a != b

def test_beacon():
    ap = AccessPoint()
    beacon = ap.send_beacon()
    assert beacon is not None

def test_probe_request():
    ap = AccessPoint()
    st = Station()
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    assert probe_request is not None

def test_valid_unsaved_probe_response():
    ap = AccessPoint()
    st = Station()
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    probe_response = ap.send_probe_response(probe_request)
    success, ssid, ap_pk = st.verify_probe_response(probe_response)
    assert ssid is not None and ap_pk is not None
    assert not success

def test_valid_saved_probe_response():
    ap = AccessPoint()
    st = Station()
    st.save_ap(ap)
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    probe_response = ap.send_probe_response(probe_request)
    success, ssid, ap_pk = st.verify_probe_response(probe_response)
    assert ssid is not None and ap_pk is not None
    assert success

def test_karma():
    adversary = AccessPoint()
    ap = AccessPoint()
    st = Station()
    st.save_ap(ap)
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    with pytest.raises(ValueError):
        probe_response = adversary.send_probe_response(probe_request)
        _, _, _ = st.verify_probe_response(probe_response)

def test_reverse_karma():
    ap = AccessPoint()
    st = Station()
    st.save_ap(ap)
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    assert not ap.ssid in str(probe_request.contents)

def test_beacon_spam():
    ap = AccessPoint()
    st = Station()
    beacon = ap.send_beacon()
    _ = st.send_probe_request(beacon)
    beacon = ap.send_beacon()
    with pytest.raises(ValueError):
        _ = st.send_probe_request(beacon)

def test_probe_response_spam():
    ap = AccessPoint()
    st = Station()
    st.save_ap(ap)
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    probe_response = ap.send_probe_response(probe_request)
    _, _, _ = st.verify_probe_response(probe_response)
    with pytest.raises(ValueError):
        _, _, _ = st.verify_probe_response(probe_response)

def test_probe_response_timeout():
    ap = AccessPoint()
    st = Station()
    st.save_ap(ap)
    beacon = ap.send_beacon()
    probe_request = st.send_probe_request(beacon)
    probe_response = ap.send_probe_response(probe_request)
    time.sleep(1)
    with pytest.raises(ValueError):
        _, _, _ = st.verify_probe_response(probe_response)