import numpy as np
import matplotlib.pyplot as plt

def pltbar(n_groups, bar_width, data, labels, xlabels):
    
    
    fig, ax = plt.subplots()
    index = np.arange(n_groups)
    opacity = 1
    
    count = 0
    rects = []
    hatchs = ['', '', '', '///', '\\\\']
    presetColor = ['#111111', '#AAAFAA', '#44444F', '#FFFFFF', '#CCCCCF']
    
    for item in data:
        for x,y in zip(index + count * bar_width, item):
            if y == 0:
                continue
            plt.text(x, y + 0.02, y, ha = 'center', va = 'bottom', fontsize = 9)
        
        ax.bar(index + count * bar_width, item, bar_width - 0.05,
                           alpha = opacity,
                           color = presetColor[count],
                           edgecolor = '#000000',
                           hatch = hatchs[count],
                           label = labels[count])
        count += 1
    
    ax.set_ylabel('TEST')
    ax.set_xticks([index[x] + 0.5 * bar_width for x in range(n_groups)])
    ax.set_xticklabels(xlabels)
    ax.legend()
    
    fig.tight_layout()
    plt.show()

def pltpoly():
    pass