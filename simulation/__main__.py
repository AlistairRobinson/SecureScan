from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from typing import List
from scipy.stats import entropy
from matplotlib import pyplot as plt
import matplotlib
import numpy as np
import argparse, random, timeit, Levenshtein

def simulate(history:List[Frame]) -> bool:
    st = random.choice(stations)
    ap = random.choice(aps)
    valid = bool(random.getrandbits(1))
    if valid:
        st.saved.add((ap.ssid, ap.key.publickey().exportKey()))
    beacon = ap.send_beacon()
    request = st.send_probe_request(beacon)
    response = ap.send_probe_response(request)
    assert st.verify_probe_response(response) == valid
    if valid:
        st.saved.remove((ap.ssid, ap.key.publickey().exportKey()))
    history.append(beacon)
    history.append(request)
    history.append(response)
    return True

parser = argparse.ArgumentParser()
parser.add_argument("-v", help = "operate simulation in verbose mode", action = 'store_true')
parser.add_argument("-t", help = "display timing information for protocol stages", action = 'store_true')
parser.add_argument("-p", help = "plot data to a given file")
parser.add_argument("-n", help = "the number of iterations to perform")
parser.add_argument("-s", help = "the number of stations to simulate")
parser.add_argument("-a", help = "the number of access points to simulate")
parser.add_argument("--levenshtein", help = "calculate Levenshtein distance in simulated data", action = 'store_true')
parser.add_argument("--entropy", help = "calculate Shannon entropy in simulated data", action = 'store_true')
parser.add_argument("--all", help = "perform all possible analysis on simulated data", action = 'store_true')
args = parser.parse_args()

n = 100
s = 1
a = 1
p = ""
v = False
t = False
levenshtein_set = False
entropy_set = False

if args.v:
    v = True
if args.t:
    t = True
if args.p:
    p = args.p
if args.n:
    n = int(args.n)
if args.s:
    s = int(args.s)
if args.a:
    a = int(args.a)
if args.levenshtein:
    levenshtein_set = True
if args.entropy:
    entropy_set = True
if args.all:
    levenshtein_set = True
    entropy_set = True

print("Beginning simulation with %d stations, %d access points, %d repetitions" % (s, a, n))

stations = [Station() for i in range(0, s)]
aps = [AccessPoint("AP" + str(i)) for i in range(0, a)]

history = []

for i in range(0, n):
    simulate(history)

if v:
    for h in history:
        print(h)

dist = [[] for i in range(0, 10000)]

l = 0
m = 0
n = 0
for f in history:
    i = 0
    if f.type != FrameType['ProbeRequest']:
        continue
    if entropy_set:
        for c in str(f.contents):
            dist[i].append(c)
            i += 1
    for h in history:
        if f != h and f.type == h.type:
            assert f.source != h.source
            assert f.contents != h.contents
            if levenshtein_set:
                d = Levenshtein.distance(str(f.contents), str(h.contents))
                if d < m or m == 0:
                    m = d
                l += d
                n += 1

if entropy_set:
    entropies = []
    for d in dist:
        if d == []:
            continue
        values, counts = np.unique(d, return_counts=True)
        entropies.append(entropy(counts))
    plt.plot(entropies)
    plt.show()
    if p != "":
        plt.savefig(p)

print("All simulations completed, no anomalies")
if t:
    time = timeit.timeit("simulate([])", "from __main__ import simulate", number = 10) / 10
    print("Average Handshake time: \t" + str(time)[:5] + "s")
if levenshtein_set:
    print("Average Levenshtein distance: \t%d" % (l / n))
    print("Minimum Levenshtein distance: \t%d" % m)
if entropy_set:
    print("Total entropy: \t\t\t%d" % sum(entropies))