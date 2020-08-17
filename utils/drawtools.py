import numpy as np
import matplotlib.pyplot as plt

def pltbar(n_groups, bar_width, data, labels, xlabels, ytext, lposition, xtext, title):
    """
    :n_groups: number of samples
    """
    
    fig, ax = plt.subplots()
    index = np.arange(n_groups) * bar_width
    opacity = 1
    
    count = 0
    hatchs = ['///', '', '\\\\',  '']
    presetColor = ['#FFFFFF', '#CCCCCF', '#AAAFAA', '#111111', '#44444F']
    
    for item in data:
        for x,y in zip(index + 0.5 * count * bar_width, item):
            if y == 0:
                continue
            plt.text(x, y + 0.02, y, ha = 'center', va = 'bottom', fontsize = 9)
        
        ax.bar(index + 0.5 * count * bar_width, item, bar_width / 3,
                           alpha = opacity,
                           color = presetColor[count],
                           edgecolor = '#000000',
                           label = labels[count],
                           hatch = hatchs[count])
        count += 1
    
    ax.set_ylabel(ytext)
    ax.set_xticks([(x + 0.25) * bar_width for x in np.arange(n_groups)])
    ax.set_xticklabels(xlabels)
    ax.legend(loc=lposition)
    ax.set_xlabel(xtext)
    
    fig.tight_layout()
    plt.show()   
    fig.savefig('./illustration/' + title + '.pdf')

def pltpoly(n_groups, data, labels, xlabels, ytext, lposition, xtext, title, show_num = True):
    """
    :n_groups: sample size
    """    
    fig, ax = plt.subplots()
    index = np.arange(n_groups)
    opacity = 1    
    count = 0
    markers = ['p', 'd', '^', 'o']
    markercolors = ['white', '#CCCCCF', '#AAAFAA', 'black']
    
    
    for item in data:
        if show_num:
            for x,y in zip(index, item):
                if y == 0:
                    continue
                plt.text(x, y + 0.4, y, ha = 'center', va = 'bottom', fontsize = 9)
        ax.plot(index, 
                item,
                linestyle = '-',
                linewidth = 2,
                color = 'black',
                marker = markers[count],
                markersize = 6,
                markeredgecolor = 'black',
                markerfacecolor = markercolors[count],
                label = labels[count])
        count += 1
    
    ax.set_ylabel(ytext)
    ax.set_xticks([x for x in np.arange(n_groups)])
    ax.set_xticklabels(xlabels)
    ax.legend(loc=lposition)
    ax.set_xlabel(xtext)
    
    fig.tight_layout()
    plt.show()
    fig.savefig('./illustration/' + title + '.pdf')