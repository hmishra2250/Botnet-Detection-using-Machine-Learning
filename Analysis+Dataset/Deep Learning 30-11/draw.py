import pandas as pd
from sys import argv
df = pd.read_csv(argv[1])
import matplotlib.pyplot as plt
l1, = plt.plot(df['epoch'].as_matrix(),df['acc'].as_matrix(),'r-',label='Training Accuracy')
l2, = plt.plot(df['epoch'].as_matrix(),df['val_acc'].as_matrix(),'g-',label='Test Accuracy')
#plt.ylim([1000,1400])
#lg1 = plt.legend(handles=[l1],loc = 1) 				#Multiple legends cant be genrated through multiple calls of legend
#ax = plt.gca().add_artist(lg1)
plt.legend(loc = 'lower right')
plt.show()

