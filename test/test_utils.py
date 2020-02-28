from secure_scan.utils import fragment, get_key, get_mac, get_ssid
from string import ascii_letters

def test_fragment():
    assert fragment("ABC", 9) == ["ABC"]
    assert fragment("ABC", 3) == ["ABC"]
    assert fragment("ABC", 2) == ["AB", "C"]
    assert all(len(x) <= 5 for x in fragment(ascii_letters, 5))

def test_get_key():
    assert get_key().can_encrypt()
    assert get_key().has_private()
    assert get_key().can_sign()

def test_get_mac():
    assert len(get_mac()) == 12

def test_get_ssid():
    assert all(c in ascii_letters for c in get_ssid())