from matplotlib import pyplot as plt
from plotter import plot

plot.plot_classifier_results('results/classifier_results.csv')
plot.plot_time_results('results/time_results.csv')

for deg in range(0, 360):
    for i in plt.get_fignums():
        f = plt.figure(i)
        for ax in f.get_axes():
            ax.view_init(30, deg)
    plt.draw()
    plt.pause(.00001)
