import pandas as pd
from sys import argv
from pylab import savefig
df = pd.read_csv(argv[1])
import matplotlib.pyplot as plt
l1, = plt.plot(df['epoch'].as_matrix(),df['loss'].as_matrix(),'r-',label='Training Loss')
l2, = plt.plot(df['epoch'].as_matrix(),df['val_loss'].as_matrix(),'g-',label='Validation Loss')
plt.ylim([0,5000])
#lg1 = plt.legend(handles=[l1],loc = 1) 				#Multiple legends cant be genrated through multiple calls of legend
#ax = plt.gca().add_artist(lg1)
plt.legend(loc = 'upper right')
savefig(argv[1]+'-figure.png',bbox_inches='tight')
plt.show()

