import numpy as np
import matplotlib.pyplot as plt

def pltbar(n_groups, bar_width, data, labels, xlabels, ytext):
    """
    :n_groups: number of samples
    """
    
    fig, ax = plt.subplots()
    index = np.arange(n_groups)
    opacity = 1
    
    count = 0
    rects = []
    hatchs = ['///', '', '\\\\',  '']
    presetColor = ['#FFFFFF', '#CCCCCF', '#AAAFAA', '#111111', '#44444F']
    
    for item in data:
        for x,y in zip(index + count * bar_width, item):
            if y == 0:
                continue
            plt.text(x, y + 0.02, y, ha = 'center', va = 'bottom', fontsize = 9)
        
        ax.bar(index + count * bar_width, item, bar_width - 0.1,
                           alpha = opacity,
                           color = presetColor[count],
                           edgecolor = '#000000',
                           label = labels[count],
                           hatch = hatchs[count])
        count += 1
    
    ax.set_ylabel(ytext)
    ax.set_xticks([x + 0.5 * bar_width for x in range(n_groups + 1)])
    ax.set_xticklabels(xlabels)
    ax.legend(loc=7)
    
    fig.tight_layout()
    plt.show()

def pltpoly():
    pass