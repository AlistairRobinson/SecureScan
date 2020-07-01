from matplotlib import pyplot as plt
import pandas as pd
import numpy as np

data = pd.read_csv('results/classifier_results.csv')
data['id'] = data['acc'] * data['s']
secure_scan = data[data['protocol'] == 'secure_scan']
standard = data[data['protocol'] == 'standard']

for axis in ['s', 'a', 'p']:
    for v in data[axis].unique():
        print("secure_scan", axis, v,
              np.min(secure_scan[secure_scan[axis] == v]['id']),
              np.quantile(secure_scan[secure_scan[axis] == v]['id'], 0.25),
              np.median(secure_scan[secure_scan[axis] == v]['id']),
              np.quantile(secure_scan[secure_scan[axis] == v]['id'], 0.75),
              np.max(secure_scan[secure_scan[axis] == v]['id']), sep=",")

for axis in ['s', 'a', 'p']:
    for v in data[axis].unique():
        print("standard", axis, v,
              np.min(standard[standard[axis] == v]['id']),
              np.quantile(standard[standard[axis] == v]['id'], 0.25),
              np.median(standard[standard[axis] == v]['id']),
              np.quantile(standard[standard[axis] == v]['id'], 0.75),
              np.max(standard[standard[axis] == v]['id']), sep=",")