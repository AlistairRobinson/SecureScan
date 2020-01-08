from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from typing import List
from scipy.stats import entropy
from scipy.spatial.distance import jensenshannon
from matplotlib import pyplot as plt
import matplotlib
import numpy as np
import argparse, random, timeit, string, Levenshtein

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
    if args.v:
        print(beacon)
        print(request)
        print(response)
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
parser.add_argument("--r-entropy", help = "calculate relative entropy in simulated data", action = 'store_true')
parser.add_argument("--jensen-shannon", help = "calculate Jensen Shannon distance in simulated data", action = 'store_true')
parser.add_argument("--all", help = "perform all possible analysis on simulated data", action = 'store_true')
args = parser.parse_args()

n = 100
s = 1
a = 1
p = ""

if args.p:
    p = args.p
if args.n:
    n = int(args.n)
if args.s:
    s = int(args.s)
if args.a:
    a = int(args.a)

print("Beginning simulation with %d stations, %d access points, %d repetitions" % (s, a, n))

stations = [Station() for i in range(0, s)]
aps = [AccessPoint("AP" + str(i)) for i in range(0, a)]

history = []

for i in range(0, n):
    simulate(history)

global_dist = [[] for i in range(0, 10000)]
local_dists = {}

for f in history:
    if f.type != FrameType['ProbeRequest']:
        continue
    if args.entropy or args.all:
        for c in range(0, len(str(f.contents))):
            global_dist[c].append(str(f.contents)[c])
    if args.r_entropy or args.all:
        values, counts = np.unique(list(str(f.contents) + string.printable), return_counts = True)
        local_dists[str(f.sent_at)] = counts

l_sum = 0
l_min = 0
r_sum = 0
r_min = 0
js_sum = 0
js_min = 0
n = 0

for f in history:
    if f.type != FrameType['ProbeRequest']:
        continue
    for h in history:
        if f != h and f.type == h.type:
            assert f.source != h.source
            assert f.contents != h.contents
            if args.levenshtein or args.all:
                l = Levenshtein.distance(str(f.contents), str(h.contents))
                if l < l_min or l_min == 0:
                    l_min = l
                l_sum += l
            if args.r_entropy or args.all:
                r = entropy(local_dists[str(f.sent_at)], local_dists[str(h.sent_at)])
                if r < r_min or r_min == 0:
                    r_min = r
                r_sum += r
            if args.jensen_shannon or args.all:
                js = jensenshannon(local_dists[str(f.sent_at)], local_dists[str(h.sent_at)])
                if js < js_min or js_min == 0:
                    js_min = js
                js_sum += js
            n += 1

if args.entropy or args.all:
    entropies = []
    for d in global_dist:
        if d == []:
            continue
        values, counts = np.unique(d, return_counts = True)
        entropies.append(entropy(counts))
    plt.plot(entropies)
    plt.show()
    if p != "":
        plt.savefig(p)

print("All simulations completed, no anomalies")
if args.t:
    time = timeit.timeit("simulate([])", "from __main__ import simulate", number = 100) / 100
    print("Average Handshake time: \t" + str(time)[:5] + "s")
if args.levenshtein or args.all:
    print("Average Levenshtein distance: \t\t%d" % (l_sum / n))
    print("Minimum Levenshtein distance: \t\t%d" % l_min)
if args.r_entropy or args.all:
    print("Average relative entropy: \t\t" + str(r_sum / n))
    print("Minimum relative entropy: \t\t" + str(r_min))
if args.jensen_shannon or args.all:
    print("Average Jensen Shannon distance: \t" + str(js_sum / n))
    print("Minimum Jensen Shannon distance: \t" + str(js_min))
if args.entropy or args.all:
    print("Total message entropy: \t\t\t%d" % sum(entropies))