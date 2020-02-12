from matplotlib import pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from matplotlib.ticker import FuncFormatter
import numpy as np
import pandas as pd
import math

pd.options.mode.chained_assignment = None
pd.set_option('display.max_rows', None)

data = pd.read_csv('results.csv')

data['id'] = data['acc'] * data['s']
secure_scan = data[data['protocol'] == 'secure_scan']
standard = data[data['protocol'] == 'standard']

secure_scan = secure_scan.merge(secure_scan.groupby(['a', 'p'], as_index=False)['id'].mean(), on=['a', 'p'], suffixes=(('', '_mean')))
standard = standard.merge(standard.groupby(['a', 'p'], as_index=False)['id'].mean(), on=['a', 'p'], suffixes=(('', '_mean')))

plt.figure()
ax = plt.axes(projection='3d')
fig = plt.figure()

c = [1, 0.75, 0.5, 0.25]
p = [0.1, 0.01, 0.001, 0.0001]

for i in range(len(p)):

    an = fig.add_subplot(2, 2, i + 1, projection='3d')

    d = secure_scan[secure_scan['p'] == p[i]]
    ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(0, 1, c[i], 0.45))
    an.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(0, 1, c[i], 0.45))

    d = standard[standard['p'] == p[i]]
    ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(1, 0, c[i], 0.45))
    an.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(1, 0, c[i], 0.45))

    an.plot_trisurf(np.log([10, 10, 100, 100, 1000, 1000, 10000, 10000]),
                np.log([10, 10000, 10, 10000, 10, 10000, 10, 10000]),
                [1/10, 1/10, 1/100, 1/100, 1/1000, 1/1000, 1/10000, 1/10000],
                color=(1, 1, 1, 0.1))

    an.set_zlim3d(0, 1)
    an.set_xlabel('log(s)')
    an.set_ylabel('log(a)')
    an.set_zlabel('acc')
    an.set_title("Classifier Accuracy on log(s) and log(a) (p = {})".format(p[i]))

ax.plot_trisurf(np.log([10, 10, 100, 100, 1000, 1000, 10000, 10000]),
                np.log([10, 10000, 10, 10000, 10, 10000, 10, 10000]),
                [1/10, 1/10, 1/100, 1/100, 1/1000, 1/1000, 1/10000, 1/10000],
                color=(1, 1, 1, 0.1))

ax.set_zlim3d(0, 1)
ax.set_xlabel('log(s)')
ax.set_ylabel('log(a)')
ax.set_zlabel('acc')
ax.set_title("Classifier Accuracy on log(s) and log(a)")

plt.figure()
ax = plt.axes(projection='3d')
fig = plt.figure()

for i in range(len(p)):

    an = fig.add_subplot(2, 2, i + 1, projection='3d')

    d = secure_scan[secure_scan['p'] == p[i]]
    ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(0, 1, c[i], 0.45))
    an.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(0, 1, c[i], 0.45))

    d = standard[standard['p'] == p[i]]
    ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(1, 0, c[i], 0.45))
    an.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(1, 0, c[i], 0.45))

    an.plot_trisurf(np.log([10, 10, 10000, 10000]),
                np.log([10, 10000, 10, 10000]),
                [1, 1, 1, 1], color=(1, 1, 1, 0.1))

    an.set_zlim3d(0, 1000)
    an.set_xlabel('log(s)')
    an.set_ylabel('log(a)')
    an.set_zlabel('s * acc')
    an.set_title("Device Identifiability on log(s) and log(a) (p = {})".format(p[i]))

ax.plot_trisurf(np.log([10, 10, 10000, 10000]),
                np.log([10, 10000, 10, 10000]),
                [1, 1, 1, 1], color=(1, 1, 1, 0.1))

ax.set_zlim3d(0, 1000)
ax.set_xlabel('log(s)')
ax.set_ylabel('log(a)')
ax.set_zlabel('s * acc')
ax.set_title("Device Identifiability on log(s) and log(a)")
plt.show()