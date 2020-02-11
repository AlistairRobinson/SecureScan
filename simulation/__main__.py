from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from typing import List
from scipy.stats import entropy
from scipy.spatial.distance import jensenshannon
from sklearn.model_selection import KFold
from sklearn.naive_bayes import GaussianNB
from matplotlib import pyplot as plt
import matplotlib
import progressbar
import numpy as np
import pandas as pd
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
        return False
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
parser.add_argument("-e", help = "analyse and plot Shannon entropy and Jensen-Shannon distance", action = 'store_true')
parser.add_argument("-b", help = "perform Bayesian classification on probe requests", action = 'store_true')
parser.add_argument("-n", help = "the number of iterations to perform")
parser.add_argument("-s", help = "the number of stations to simulate")
parser.add_argument("-a", help = "the number of access points to simulate")
parser.add_argument("-p", help = "the probability of a station having a connection to an AP")
parser.add_argument("--protocol", help = "the handshake protocol to use")
parser.add_argument("--csv", help = "the .csv file to write results to")
args = parser.parse_args()

n = 100
s = 1
a = 1
p = 0.5

if args.n:
    n = int(args.n)
if args.s:
    s = int(args.s)
if args.a:
    a = int(args.a)
if args.p:
    p = float(args.p)

if not args.protocol or args.protocol.lower() not in ["standard", "secure_scan"]:
    args.protocol = "secure_scan"

print("\nInitialising {} stations...".format(s))
stations = [Station(i) for i in progressbar.progressbar(range(s), term_width=100)]
print("Initialising {} access points...".format(a))
aps = [AccessPoint(''.join(random.choice(string.ascii_lowercase) for i in range(8)), i) for i in progressbar.progressbar(range(a), term_width=100)]
print("Beginning simulation with {} stations, {} access points, p = {}, n = {}...".format(s, a, p, n))

for station in stations:
    for ap in aps:
        if p > random.random():
            station.saved.add((ap.ssid, ap.key.publickey().exportKey()))

history = []

for i in progressbar.progressbar(range(n), term_width=100):
    if args.protocol.lower() == "standard":
        while not simulate_standard(history):
            pass
    if args.protocol.lower() == "secure_scan":
        simulate_secure_scan(history)

print("All simulations completed, no anomalies")

probe_requests = [h for h in filter(lambda f: f.type == FrameType['ProbeRequest'], history)]
unique_probe_requests = list(set([str(p.contents) for p in probe_requests]))

if args.e:

    global_dist = [[] for i in range(0, 10000)]
    local_dists = {}

    print("Beginning Shannon Entropy analysis...")
    with progressbar.ProgressBar(max_value=len(probe_requests), term_width=100) as bar:
        progress = 0
        for f in probe_requests:
            for c in range(0, len(str(f.contents))):
                global_dist[c].append(str(f.contents)[c])
            values, counts = np.unique(list(str(f.contents) + string.printable), return_counts = True)
            local_dists[str(f.sent_at)] = counts - 1
            progress += 1
            bar.update(progress)

    js = []

    print("Beginning Jensen-Shannon Distance analysis...")
    for f in progressbar.progressbar(range(len(probe_requests)), term_width=100):
        for h in range(f + 1, len(probe_requests)):
            js.append(jensenshannon(local_dists[str(probe_requests[f].sent_at)],
                                    local_dists[str(probe_requests[h].sent_at)]))

    entropies = []
    for d in global_dist:
        if d == []:
            continue
        values, counts = np.unique(d, return_counts = True)
        entropies.append(entropy(counts))

    plt.figure()
    plt.plot(entropies)
    plt.title("Probe Request Content Entropy")
    plt.xlabel("Probe Request Content Character Position")
    plt.ylabel("Shannon Entropy")
    plt.axis('tight')
    plt.show()
    plt.savefig("{}_{}_{}_{}_epy".format(args.protocol, s, a, n))
    plt.figure()
    plt.hist(js)
    plt.title("Probe Request Content Jensen-Shannon Distribution")
    plt.xlabel("Jensen-Shannon Distance")
    plt.ylabel("Occurrences")
    plt.axis('tight')
    plt.show()
    plt.savefig("{}_{}_{}_{}_jsd".format(args.protocol, s, a, n))
    plt.figure()
    pd.Series([str(p.contents) for p in probe_requests]).value_counts().plot(kind = 'area')
    plt.title("Probe Request Content Distribution")
    plt.xlabel("Probe Request Content")
    plt.ylabel("Occurrences Density")
    plt.axis('tight')
    if args.protocol.lower() == "secure_scan":
        plt.gca().axes.xaxis.set_ticklabels([])
    plt.show()
    plt.savefig("{}_{}_{}_{}_hst".format(args.protocol, s, a, n))

if args.b:
    X = np.array([[hash(p.source), hash(p.destination), hash(str(p.contents))] for p in probe_requests])
    y = np.array([p.uid for p in probe_requests])
    acc = []

    print("Training Naive Bayes classifier...")
    with progressbar.ProgressBar(max_value=10, term_width=100) as bar:
        progress = 0
        for train_i, test_i in KFold(n_splits=10).split(X):
            X_train, X_test = X[train_i], X[test_i]
            y_train, y_test = y[train_i], y[test_i]
            y_pred = GaussianNB().fit(X_train, y_train).predict(X_test)
            acc.append((y_pred == y_test).sum() / len(y_pred))
            progress += 1
            bar.update(progress)

print("\nAnalysis complete\n")

if args.t:
    if args.protocol.lower() == "standard":
        time = timeit.timeit("simulate_standard([])",
                             "from __main__ import simulate_standard", number = 100) / 100
    if args.protocol.lower() == "secure_scan":
        time = timeit.timeit("simulate_secure_scan([])",
                            "from __main__ import simulate_secure_scan", number = 100) / 100
    print("Average handshake time: \t\t\t{}s".format(time))
print("Total Probe Requests:  \t\t\t\t{}".format(len(probe_requests)))
print("Unique Probe Requests: \t\t\t\t{}".format(len(unique_probe_requests)))
if args.e:
    print("Average Jensen-Shannon distance: \t\t{}".format(sum(js)/len(js)))
    print("Minimum Jensen-Shannon distance: \t\t{}".format(min(js)))
    print("Std-Dev Jensen-Shannon distance: \t\t{}".format(np.std(js)))
    print("Total message entropy: \t\t\t\t{}".format(sum(entropies)))
if args.b:
    print("Bayesian classifier accuracies: \t\t{}".format(acc))
    print("Average Bayesian classifier accuracy: \t\t{}".format(np.mean(acc)))
print("")

if args.csv:
    with open(args.csv, 'a') as f:
        f.write("\n{},{},{},{},{},{},{}".format(args.protocol, n, s, a, p, len(unique_probe_requests), np.mean(acc)))