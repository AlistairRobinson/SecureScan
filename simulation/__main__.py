from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from typing import List
from scipy.stats import entropy
from scipy.spatial.distance import jensenshannon
from matplotlib import pyplot as plt
import matplotlib
import numpy as np
import argparse, random, timeit, string

def simulate_secure_scan(history:List[Frame]) -> bool:
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
    if args.v:
        print(beacon)
        print(request)
        print(response)
    return True

def simulate_standard(history:List[Frame]) -> bool:
    st = random.choice(stations)
    ap = random.choice(aps)
    valid = (ap.ssid in [i[0] for i in st.saved])
    beacon = ap.send_beacon()
    history.append(beacon)
    if args.v:
        print(beacon)
    request = st.send_probe_request(beacon)
    if not valid:
        assert request is None
    else:
        response = ap.send_probe_response(request)
        history.append(request)
        history.append(response)
        if args.v:
            print(request)
            print(response)
    return True

parser = argparse.ArgumentParser()
parser.add_argument("-v", help = "operate simulation in verbose mode", action = 'store_true')
parser.add_argument("-t", help = "display timing information for protocol stages", action = 'store_true')
parser.add_argument("-p", help = "plot Shannon Entropy and Jensen-Shannon distance", action = 'store_true')
parser.add_argument("-n", help = "the number of iterations to perform")
parser.add_argument("-s", help = "the number of stations to simulate")
parser.add_argument("-a", help = "the number of access points to simulate")
parser.add_argument("--protocol", help = "the handshake protocol to use")
parser.add_argument("--distribution", help = "the access point distribution to use")
args = parser.parse_args()

n = 100
s = 1
a = 1
p = ""

if args.n:
    n = int(args.n)
if args.s:
    s = int(args.s)
if args.a:
    a = int(args.a)

if not args.protocol or args.protocol.lower() not in ["standard", "lindqvist", "secure_scan"]:
    print("Using default secure_scan protocol")
    args.protocol = "secure_scan"

if not args.distribution or args.distribution.lower() not in ["uniform", "cumulative"]:
    print("Using default cumulative distribution")
    args.distribution = "cumulative"

print("Beginning simulation with %d stations, %d access points, %d repetitions" % (s, a, n))

stations = [Station() for i in range(0, s)]
aps = [AccessPoint(''.join(random.choice(string.ascii_lowercase) for i in range(8))) for i in range(0, a)]

for station in stations:
    for i in range(0, random.randint(0, len(aps))):
        if args.distribution.lower() == "cumulative":
            station.saved.add((aps[i].ssid, aps[i].key.publickey().exportKey()))
        if args.distribution.lower() == "uniform":
            ap = random.choice(aps)
            station.saved.add((ap.ssid, ap.key.publickey().exportKey()))

history = []

for i in range(0, n):
    if args.protocol.lower() == "standard":
        simulate_standard(history)
    if args.protocol.lower() == "secure_scan":
        simulate_secure_scan(history)

global_dist = [[] for i in range(0, 10000)]
local_dists = {}

for f in history:
    if f.type != FrameType['ProbeRequest']:
        continue
    for c in range(0, len(str(f.contents))):
        global_dist[c].append(str(f.contents)[c])
    values, counts = np.unique(list(str(f.contents) + string.printable), return_counts = True)
    local_dists[str(f.sent_at)] = counts - 1

js = []

for f in history:
    if f.type != FrameType['ProbeRequest']:
        continue
    for h in history:
        if f != h and f.type == h.type:
            js.append(jensenshannon(local_dists[str(f.sent_at)], local_dists[str(h.sent_at)]))

entropies = []
for d in global_dist:
    if d == []:
        continue
    values, counts = np.unique(d, return_counts = True)
    entropies.append(entropy(counts))

if args.p:
    plt.figure()
    plt.plot(entropies)
    plt.title("Probe Request Message Entropy")
    plt.xlabel("Probe Request Character Position")
    plt.ylabel("Shannon Entropy")
    plt.axis('tight')
    plt.show()
    plt.savefig(args.protocol + "_" + str(s) + "_" + str(a) + "_" + str(n) + "_epy")
    plt.figure()
    plt.plot(sorted(js))
    plt.title("Sorted Probe Request Jensen-Shannon Distances")
    plt.xlabel("")
    plt.ylabel("Jensen-Shannon Distance")
    plt.axis('tight')
    plt.show()
    plt.savefig(args.protocol + "_" + str(s) + "_" + str(a) + "_" + str(n) + "_jsd")

print("All simulations completed, no anomalies")
if args.t:
    if args.protocol.lower() == "standard":
        time = timeit.timeit("simulate_standard([])",
                             "from __main__ import simulate_standard", number = 100) / 100
    if args.protocol.lower() == "secure_scan":
        time = timeit.timeit("simulate_secure_scan([])",
                            "from __main__ import simulate_secure_scan", number = 100) / 100
    print("Average handshake time: \t\t" + str(time) + "s")
print("Average Jensen Shannon distance: \t" + str(sum(js)/len(js)))
print("Minimum Jensen Shannon distance: \t" + str(min(js)))
print("Total message entropy: \t\t\t%d" % sum(entropies))