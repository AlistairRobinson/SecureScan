from simulation.actors import Station, AccessPoint

s = Station()
a = AccessPoint("Example")

beacon = a.send_beacon()
print(beacon)
request = s.send_probe_request(beacon)
print(request)
response = a.send_probe_response(request)
print(response)
assert s.verify_probe_response(response)