import random
import time
import numpy as np
import progressbar as pb
import simulation.simulator as sim
from simulation.frames import FrameType
from simulation.parser import construct_parser

def main():
    """ Executes a simulation of a network handshake protocol
    """

    args = construct_parser().parse_args()

    n = int(args.n) if args.n else 10
    s = int(args.s) if args.s else 1
    a = int(args.a) if args.a else 1
    p = float(args.p) if args.p else 1
    if args.protocol and args.protocol.lower() in ["standard", "secure_scan"]:
        protocol = args.protocol.lower()
    else:
        protocol = "secure_scan"

    print("")
    print("Initialising {} stations...".format(s))
    stations = sim.get_stations(s)
    print("Initialising {} access points...".format(a))
    aps = sim.get_access_points(a)
    print("Associating stations and access points with p = {}...".format(p))
    for i in pb.progressbar(range(len(stations)), term_width=100):
        station = stations[i]
        for ap in aps:
            if p > random.random():
                station.saved.add((ap.ssid, ap.key.publickey().exportKey()))
        if len(station.saved) == 0:
            ap = random.choice(aps)
            station.saved.add((ap.ssid, ap.key.publickey().exportKey()))

    print("Beginning simulation with {} stations, {} access points, " \
          "p = {}, n = {}...".format(s, a, p, n))

    history = []
    duration = 0

    for _ in pb.progressbar(range(n), term_width=100):
        st = time.time()
        if protocol == "standard":
            while not sim.simulate_standard(stations, aps, history, args.v):
                st = time.time()
        if protocol == "secure_scan":
            sim.simulate_secure_scan(stations, aps, history, args.v)
        duration += time.time() - st

    print("All simulations completed, no anomalies")

    probe_requests = list(filter(lambda f: f.type == FrameType['ProbeRequest'],
                                 history))
    u_probe_requests = list({str(p.contents) for p in probe_requests})

    x = np.array([[hash(p.source), hash(p.destination),
                   hash(str(p.contents))] for p in probe_requests])
    y = np.array([p.uid for p in probe_requests])

    print("Training Naive Bayes classifier...")
    acc = sim.train_classifier(x, y, 10)

    print("\nAnalysis complete\n")

    print("Total Probe Requests:  \t\t\t\t{}".format(len(probe_requests)))
    print("Unique Probe Requests: \t\t\t\t{}".format(len(u_probe_requests)))
    print("Average handshake time: \t\t\t{}s".format(duration / n))
    print("Bayesian classifier accuracies: \t\t{}".format(acc))
    print("Average Bayesian classifier accuracy: \t\t{}".format(np.mean(acc)))
    print("")

    if args.csv:
        with open(args.csv, 'a') as f:
            f.write("\n{},{},{},{},{},{},{}".format(protocol, n, s, a, p,
                                                    len(u_probe_requests),
                                                    np.mean(acc)))

main()
