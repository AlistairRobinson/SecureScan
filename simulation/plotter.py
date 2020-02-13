from matplotlib import pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from matplotlib.ticker import FuncFormatter
import numpy as np
import pandas as pd
import math

pd.options.mode.chained_assignment = None
pd.set_option('display.max_rows', None)

def construct_axis(a, zmin, zmax, xl, yl, zl, t):
    a.set_zlim3d(zmin, zmax)
    a.set_xlabel(xl)
    a.set_ylabel(yl)
    a.set_zlabel(zl)
    a.set_title(t)

def plot_classifier_results(f):

    data = pd.read_csv(f)

    data['id'] = data['acc'] * data['s']
    secure_scan = data[data['protocol'] == 'secure_scan']
    standard = data[data['protocol'] == 'standard']

    secure_scan = secure_scan.merge(secure_scan.groupby(['a', 'p'], as_index=False)['id'].mean(), on=['a', 'p'], suffixes=(('', '_mean')))
    standard = standard.merge(standard.groupby(['a', 'p'], as_index=False)['id'].mean(), on=['a', 'p'], suffixes=(('', '_mean')))

    c = [1, 0.75, 0.5, 0.25]
    p = [0.1, 0.01, 0.001, 0.0001]

    plt.figure()
    main_ax = plt.axes(projection='3d')
    sub_ax = {}
    fig = plt.figure()

    for i in range(len(p)):

        sub_ax[i] = fig.add_subplot(2, 2, i + 1, projection='3d')

        d = secure_scan[secure_scan['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(0, 1, c[i], 0.45))
        sub_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(0, 1, c[i], 0.45))

        d = standard[standard['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(1, 0, c[i], 0.45))
        sub_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']), d['acc'], color=(1, 0, c[i], 0.45))

        sub_ax[i].plot_trisurf(np.log([10, 10, 100, 100, 1000, 1000, 10000, 10000]),
                               np.log([10, 10000, 10, 10000, 10, 10000, 10, 10000]),
                               [1/10, 1/10, 1/100, 1/100, 1/1000, 1/1000, 1/10000, 1/10000],
                               color=(1, 1, 1, 0.1))

        construct_axis(sub_ax[i], 0, 1, 'log(s)', 'log(a)', 'acc', "Classifier Accuracy on log(s) and log(a) (p = {})".format(p[i]))

    main_ax.plot_trisurf(np.log([10, 10, 100, 100, 1000, 1000, 10000, 10000]),
                         np.log([10, 10000, 10, 10000, 10, 10000, 10, 10000]),
                         [1/10, 1/10, 1/100, 1/100, 1/1000, 1/1000, 1/10000, 1/10000],
                         color=(1, 1, 1, 0.1))

    construct_axis(main_ax, 0, 1, 'log(s)', 'log(a)', 'acc', "Classifier Accuracy on log(s) and log(a)")

    plt.figure()
    main_ax = plt.axes(projection='3d')
    sub_ax = {}
    fig = plt.figure()

    for i in range(len(p)):

        sub_ax[i] = fig.add_subplot(2, 2, i + 1, projection='3d')

        d = secure_scan[secure_scan['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(0, 1, c[i], 0.45))
        sub_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(0, 1, c[i], 0.45))

        d = standard[standard['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(1, 0, c[i], 0.45))
        sub_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']), d['id'], color=(1, 0, c[i], 0.45))

        sub_ax[i].plot_trisurf(np.log([10, 10, 10000, 10000]),
                               np.log([10, 10000, 10, 10000]),
                               [1, 1, 1, 1], color=(1, 1, 1, 0.1))

        construct_axis(sub_ax[i], 0, 1000, 'log(s)', 'log(a)', 'acc', "Device Identifiability on log(s) and log(a) (p = {})".format(p[i]))

    main_ax.plot_trisurf(np.log([10, 10, 10000, 10000]),
                         np.log([10, 10000, 10, 10000]),
                         [1, 1, 1, 1], color=(1, 1, 1, 0.1))

    construct_axis(main_ax, 0, 1000, 'log(s)', 'log(a)', 'acc', "Device Identifiability on log(s) and log(a)")

def plot_time_results(f):

    data = pd.read_csv(f)
    plt.figure()
    main_ax = plt.axes(projection='3d')

    main_ax.plot_trisurf(np.log(data['s']), np.log(data['a']), data['standard_t'], color=(1, 0, 0, 0.75))
    main_ax.plot_trisurf(np.log(data['s']), np.log(data['a']), data['secure_scan_t'], color=(0, 1, 0, 0.75))

    construct_axis(main_ax, 0, 0.3, 'log(s)', 'log(a)', 't', "Handshake Completion Time on log(s) and log(a)")

plot_classifier_results('results/classifier_results.csv')
plot_time_results('results/time_results.csv')

for deg in range(0, 360):
    for i in plt.get_fignums():
        f = plt.figure(i)
        for ax in f.get_axes():
            ax.view_init(30, deg)
    plt.draw()
    plt.pause(.00001)