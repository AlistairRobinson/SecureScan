from matplotlib import pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
import pandas as pd

pd.options.mode.chained_assignment = None
pd.set_option('display.max_rows', None)

def construct_axis(a: Axes3D, zmin: int = 0, zmax: int = 1,
                   xl: str = "", yl: str = "", zl: str = "", t: str = ""):
    """ Construct a 3D axis with given z bounds and labels

    Args:
        a (Axes3D): The axis to construct on
        zmin (int): The minimum scale for the z axis, defaults to 0
        zmax (int): The maximum scale for the z axis, defaults to 1
        xl (str):   The label for the x axis, defaults to ""
        yl (str):   The label for the x axis, defaults to ""
        zl (str):   The label for the x axis, defaults to ""
        t (str):    The title of the axes, defaults to ""
    """
    a.set_zlim3d(zmin, zmax)
    a.set_xlabel(xl)
    a.set_ylabel(yl)
    a.set_zlabel(zl)
    a.set_title(t)

def plot_classifier_results(fname: str):
    """ Plots the classifier results stored in a file `fname`

    Args:
        fname (str): The name of a `.csv` file containing classifier results
    """
    data = pd.read_csv(fname)

    data['id'] = data['acc'] * data['s']
    secure_scan = data[data['protocol'] == 'secure_scan']
    standard = data[data['protocol'] == 'standard']

    c = [1, 0.75, 0.5, 0.25]
    p = [0.1, 0.01, 0.001, 0.0001]

    baseline_x = [10, 10, 100, 100, 1000, 1000, 10000, 10000]
    baseline_y = [10, 10000, 10, 10000, 10, 10000, 10, 10000]
    baseline_z = [1/10, 1/10, 1/100, 1/100, 1/1000, 1/1000, 1/10000, 1/10000]

    plt.figure()
    main_ax = plt.axes(projection='3d')
    s_ax = {}
    fig = plt.figure()

    for i in range(len(p)):

        s_ax[i] = fig.add_subplot(2, 2, i + 1, projection='3d')

        d = secure_scan[secure_scan['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['acc'], color=(0, 1, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['acc'], color=(0, 1, c[i], 0.45))

        d = standard[standard['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['acc'], color=(1, 0, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['acc'], color=(1, 0, c[i], 0.45))

        s_ax[i].plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                             baseline_z, color=(1, 1, 1, 0.1))

        t = "Classifier Accuracy on log(s) and log(a) (p = {})".format(p[i])
        construct_axis(s_ax[i], 0, 1, 'log(s)', 'log(a)', 'acc', t)

    main_ax.plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                         baseline_z, color=(1, 1, 1, 0.1))

    t = "Classifier Accuracy on log(s) and log(a)"
    construct_axis(main_ax, 0, 1, 'log(s)', 'log(a)', 'acc', t)

    baseline_z = [1 for i in range(8)]

    plt.figure()
    main_ax = plt.axes(projection='3d')
    s_ax = {}
    fig = plt.figure()

    for i in range(len(p)):

        s_ax[i] = fig.add_subplot(2, 2, i + 1, projection='3d')

        d = secure_scan[secure_scan['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['id'], color=(0, 1, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['id'], color=(0, 1, c[i], 0.45))

        d = standard[standard['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['id'], color=(1, 0, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             d['id'], color=(1, 0, c[i], 0.45))

        s_ax[i].plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                             baseline_z, color=(1, 1, 1, 0.1))

        t = "Device Identifiability on log(s) and log(a) (p = {})".format(p[i])
        construct_axis(s_ax[i], 0, 1000, 'log(s)', 'log(a)', 'acc * s', t)

    main_ax.plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                         baseline_z, color=(1, 1, 1, 0.1))

    t = "Device Identifiability on log(s) and log(a)"
    construct_axis(main_ax, 0, 1000, 'log(s)', 'log(a)', 'acc * s', t)

def plot_upr_results(fname: str):
    """ Plots the unique probe request results stored in a file `fname`

    Args:
        fname (str): The name of a `.csv` file containing upr results
    """
    data = pd.read_csv(fname)

    data['id'] = data['acc'] * data['s']
    secure_scan = data[data['protocol'] == 'secure_scan']
    standard = data[data['protocol'] == 'standard']

    c = [1, 0.75, 0.5, 0.25]
    p = [0.1, 0.01, 0.001, 0.0001]

    baseline_x = [10, 10, 10000, 10000]
    baseline_y = [10, 10000, 10, 10000]
    baseline_z = [10000, 10000, 10000, 10000]

    plt.figure()
    main_ax = plt.axes(projection='3d')
    s_ax = {}
    fig = plt.figure()

    for i in range(len(p)):

        s_ax[i] = fig.add_subplot(2, 2, i + 1, projection='3d')

        d = secure_scan[secure_scan['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             np.log(d['upr']), color=(0, 1, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             np.log(d['upr']), color=(0, 1, c[i], 0.45))

        d = standard[standard['p'] == p[i]]
        main_ax.plot_trisurf(np.log(d['s']), np.log(d['a']),
                             np.log(d['upr']), color=(1, 0, c[i], 0.45))
        s_ax[i].plot_trisurf(np.log(d['s']), np.log(d['a']),
                             np.log(d['upr']), color=(1, 0, c[i], 0.45))

        s_ax[i].plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                             baseline_z, color=(1, 1, 1, 0.1))

        t = "Unique Probe Requests on log(s) and log(a) (p = {})".format(p[i])
        construct_axis(s_ax[i], 0, 10, 'log(s)', 'log(a)', 'upr', t)

    main_ax.plot_trisurf(np.log(baseline_x), np.log(baseline_y),
                         np.log(baseline_z), color=(1, 1, 1, 0.1))

    t = "Unique Probe Requests on log(s) and log(a)"
    construct_axis(main_ax, 0, 10, 'log(s)', 'log(a)', 'upr', t)

def plot_time_results(fname: str):
    """ Plots the timing results stored in a file `fname`

    Args:
        fname (str): The name of a `.csv` file containing timing results
    """
    data = pd.read_csv(fname)
    plt.figure()
    main_ax = plt.axes(projection='3d')

    main_ax.plot_trisurf(np.log(data['s']), np.log(data['a']),
                         data['standard_t'], color=(1, 0, 0, 0.75))
    main_ax.plot_trisurf(np.log(data['s']), np.log(data['a']),
                         data['secure_scan_t'], color=(0, 1, 0, 0.75))

    t = "Handshake Completion Time on log(s) and log(a)"
    construct_axis(main_ax, 0, 0.3, 'log(s)', 'log(a)', 't', t)
