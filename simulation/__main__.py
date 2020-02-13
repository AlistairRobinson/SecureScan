from simulation.simulator import *
from simulation.actors import Station, AccessPoint
from simulation.frames import Frame, FrameType
from simulation.parser import construct_parser
from sklearn.model_selection import KFold
from sklearn.naive_bayes import GaussianNB
import random, time, progressbar
import progressbar as pb
import numpy as np

args = construct_parser().parse_args()
supported_protocols = ["standard", "secure_scan"]

n = int(args.n) if args.n else 10
s = int(args.s) if args.s else 1
a = int(args.a) if args.a else 1
p = float(args.p) if args.p else 1
protocol = args.protocol.lower() if args.protocol and args.protocol.lower() in supported_protocols else "secure_scan"

print("Initialising {} stations...".format(s))
stations = get_stations(s)
print("Initialising {} access points...".format(a))
aps = get_access_points(a)
print("Beginning simulation with {} stations, {} access points, p = {}, n = {}...".format(s, a, p, n))

for station in stations:
    for ap in aps:
        if p > random.random():
            station.saved.add((ap.ssid, ap.key.publickey().exportKey()))
    if len(station.saved) == 0:
        ap = random.choice(aps)
        station.saved.add((ap.ssid, ap.key.publickey().exportKey()))

history = []
duration = 0

for i in pb.progressbar(range(n), term_width=100):
    st = time.time()
    if protocol == "standard":
        while not simulate_standard(stations, aps, history, args.v):
            st = time.time()
    if protocol == "secure_scan":
        simulate_secure_scan(stations, aps, history, args.v)
    duration += time.time() - st

print("All simulations completed, no anomalies")

probe_requests = [h for h in filter(lambda f: f.type == FrameType['ProbeRequest'], history)]
unique_probe_requests = list(set([str(p.contents) for p in probe_requests]))

X = np.array([[hash(p.source), hash(p.destination), hash(str(p.contents))] for p in probe_requests])
y = np.array([p.uid for p in probe_requests])
acc = []

print("Training Naive Bayes classifier...")
with pb.ProgressBar(max_value=10, term_width=100) as bar:
    progress = 0
    for train_i, test_i in KFold(n_splits=10).split(X):
        X_train, X_test = X[train_i], X[test_i]
        y_train, y_test = y[train_i], y[test_i]
        y_pred = GaussianNB().fit(X_train, y_train).predict(X_test)
        acc.append((y_pred == y_test).sum() / len(y_pred))
        progress += 1
        bar.update(progress)

print("\nAnalysis complete\n")

print("Total Probe Requests:  \t\t\t\t{}".format(len(probe_requests)))
print("Unique Probe Requests: \t\t\t\t{}".format(len(unique_probe_requests)))
print("Average handshake time: \t\t\t{}s".format(duration / n))
print("Bayesian classifier accuracies: \t\t{}".format(acc))
print("Average Bayesian classifier accuracy: \t\t{}".format(np.mean(acc)))
print("")

if args.csv:
    with open(args.csv, 'a') as f:
        f.write("\n{},{},{},{},{},{},{}".format(protocol, n, s, a, p, len(unique_probe_requests), np.mean(acc)))