import argparse

def construct_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", help = "operate simulation in verbose mode", action = 'store_true')
    parser.add_argument("-n", help = "the number of iterations to perform")
    parser.add_argument("-s", help = "the number of stations to simulate")
    parser.add_argument("-a", help = "the number of access points to simulate")
    parser.add_argument("-p", help = "the probability of a station having a connection to an AP")
    parser.add_argument("--protocol", help = "the handshake protocol to use")
    parser.add_argument("--csv", help = "the .csv file to write results to")
    return parser