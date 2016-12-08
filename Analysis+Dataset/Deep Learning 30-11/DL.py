
# coding: utf-8

# In[1]:

## import libraries
import numpy as np
np.random.seed(123)

import pandas as pd
import subprocess
from scipy.sparse import csr_matrix, hstack
from sklearn.metrics import mean_absolute_error,matthews_corrcoef,classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.cross_validation import KFold
from sklearn.utils import shuffle
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from keras.layers.normalization import BatchNormalization
from keras.layers.core import Activation
from keras.layers.advanced_activations import PReLU
from keras.callbacks import CSVLogger,EarlyStopping, ModelCheckpoint
from keras.models import load_model


# In[2]:

## Batch generators ##################################################################################################################################

def batch_generator(X, y, batch_size, shuffle):
    #chenglong code for fiting from generator (https://www.kaggle.com/c/talkingdata-mobile-user-demographics/forums/t/22567/neural-network-for-sparse-matrices)
    number_of_batches = np.ceil(X.shape[0]/batch_size)
    counter = 0
    sample_index = np.arange(X.shape[0])
    if shuffle:
        np.random.shuffle(sample_index)
    while True:
        batch_index = sample_index[batch_size*counter:batch_size*(counter+1)]
        X_batch = X[batch_index,:].toarray()
        y_batch = y[batch_index]
        counter += 1
        yield X_batch, y_batch
        if (counter == number_of_batches):
            if shuffle:
                np.random.shuffle(sample_index)
            counter = 0

def batch_generatorp(X, batch_size, shuffle):
    number_of_batches = X.shape[0] / np.ceil(X.shape[0]/batch_size)
    counter = 0
    sample_index = np.arange(X.shape[0])
    while True:
        batch_index = sample_index[batch_size * counter:batch_size * (counter + 1)]
        X_batch = X[batch_index, :].toarray()
        counter += 1
        yield X_batch
        if (counter == number_of_batches):
            counter = 0


# ## Read Data

# In[3]:

Train = pd.read_csv('Bidirectional_Botnet_Training_Final_Flow_Based_Features.csv',verbose=False)
Test = pd.read_csv('Bidirectional_Botnet_Test_Final_Flow_Based_Features.csv',verbose=False)
print 'Done Reading'


# In[4]:

features = ['APL',
 'AvgPktPerSec',
 'IAT',
 'NumForward',
 'Protocol',
 'BytesEx',
 'BitsPerSec',
 'NumPackets',
 'StdDevLen',
 'SameLenPktRatio',
 'FPL',
 'Duration',
 'NPEx']

target = 'isBot'


# In[5]:

Train = Train[features+[target]]
Test = Test[features+[target]]
Train.head(3)


# In[6]:

ntrain = Train.shape[0]


# In[7]:

Tr_Te = pd.concat((Train,Test),axis=0)


# In[8]:

num_features = ['APL',
 'AvgPktPerSec',
 'IAT',
 'NumForward',
 'BytesEx',
 'BitsPerSec',
 'NumPackets',
 'StdDevLen',
 'SameLenPktRatio',
 'FPL',
 'Duration',
 'NPEx']
cat_features = ['Protocol']


# ## Dummify categorical variables and normalize numerical

# In[9]:

X = []
##Categorical Varialbes
for x in cat_features:
    temp = pd.get_dummies(Tr_Te[x].astype('category'))
    X.append(temp)

scaler = StandardScaler()
tmp = scaler.fit_transform(Tr_Te[num_features])
X.append(tmp)


# ## Extract Target labes

# In[10]:

Y = Tr_Te['isBot']


# ### Remove unnecessary variables

# In[11]:

del(Tr_Te,Train,Test)


# In[12]:

temp = X[0]
for i in range(1,len(X)):
    temp = np.hstack((temp,X[i]))
    
import copy
X = copy.deepcopy(temp)
print X.shape
del(temp)


# In[13]:

X_train = X[:ntrain,:]
X_test = X[ntrain:,:]
Y_train = Y[:ntrain]
Y_test = Y[ntrain:]


# In[14]:

del(X)


# In[15]:

X_train


# In[16]:

Y_train


# In[17]:

print len(X_train),len(Y_train)
print len(X_test),len(Y_test)


# In[24]:

from keras import backend as K
def custom_obj(y_true, y_pred):
    '''Calculates the Matthews correlation coefficient measure for quality
    of binary classification problems.
    '''
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_pred_neg = 1 - y_pred_pos

    y_pos = K.round(K.clip(y_true, 0, 1))
    y_neg = 1 - y_pos

    tp = K.sum(y_pos * y_pred_pos)
    tn = K.sum(y_neg * y_pred_neg)

    fp = K.sum(y_neg * y_pred_pos)
    fn = K.sum(y_pos * y_pred_neg)

    return 2.0*fn*fp/(fn+fp)


# In[25]:

from keras import backend as K
def matthews_correlation(y_true, y_pred):
    '''Calculates the Matthews correlation coefficient measure for quality
    of binary classification problems.
    '''
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_pred_neg = 1 - y_pred_pos

    y_pos = K.round(K.clip(y_true, 0, 1))
    y_neg = 1 - y_pos

    tp = K.sum(y_pos * y_pred_pos)
    tn = K.sum(y_neg * y_pred_neg)

    fp = K.sum(y_neg * y_pred_pos)
    fn = K.sum(y_pos * y_pred_neg)

    numerator = (tp * tn - fp * fn)
    denominator = K.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))

    return numerator / (denominator + K.epsilon())


# In[38]:

def nn_model():
    model = Sequential()
    
    model.add(Dense(100, input_dim = X_train.shape[1], init = 'he_normal'))
    model.add(PReLU())
    model.add(BatchNormalization())
        
    model.add(Dense(50, init = 'he_normal'))
    model.add(PReLU())
    model.add(BatchNormalization())    
    
    model.add(Dense(50, init = 'he_normal'))
    model.add(Activation('sigmoid'))
    model.add(BatchNormalization())    
    
    model.add(Dense(1, init = 'he_normal'))
    model.compile(loss = 'binary_crossentropy', optimizer = 'adam',metrics=['accuracy','fbeta_score','matthews_correlation'])
    return(model)

def nn_model_dropout():
    model = Sequential()
    
    model.add(Dense(50, input_dim = X_train.shape[1], init = 'he_normal'))
    model.add(Activation('sigmoid'))
    model.add(BatchNormalization())
    model.add(Dropout(0.4))
        
    model.add(Dense(25, init = 'he_normal'))
    model.add(Activation('sigmoid'))
    model.add(BatchNormalization())    
    model.add(Dropout(0.2))
    
    model.add(Dense(10, init = 'he_normal'))
    model.add(Activation('sigmoid'))
    model.add(BatchNormalization())    
    model.add(Dropout(0.2))
    
    model.add(Dense(1, init = 'he_normal'))
    model.compile(loss = 'binary_crossentropy', optimizer = 'adam',metrics=['accuracy','fbeta_score','matthews_correlation'])
    return(model)


# In[51]:

model = nn_model_dropout()


# In[52]:

csv_logger = CSVLogger('log2.txt')
checkpointer = ModelCheckpoint(filepath="Models/Best2.hdf5", verbose=1, save_best_only=True)
earlyStopping = EarlyStopping(monitor='val_acc', patience=10, verbose=2, mode='min')


# In[ ]:

#model.fit(X_train,Y_train,nb_epoch=200,batch_size=128,callbacks=[csv_logger,checkpointer],validation_data=(X_test,Y_test),verbose=2)
model = load_model('Models/Best2.hdf5')

# In[42]:

y_pred = model.predict_classes(X_train)
y_pred = np.reshape(y_pred,(y_pred.shape[0]))


# In[43]:

true_pred = np.array(Y_train)


# In[44]:

def print_metr(y_pred,y_true):
    print '\n',classification_report(y_pred,y_true)


# In[45]:

print_metr(y_pred,true_pred)


# In[46]:

pred_test = model.predict_classes(X_test)
true_test = np.reshape(Y_test,(Y_test.shape[0]))
print_metr(pred_test,true_test)


# In[47]:

confusion_matrix(pred_test,true_test)


# In[48]:

print sum(Y_test)


# In[49]:

print len(Y_test)-sum(Y_test)


# In[50]:

print sum(Y_train),len(Y_train)-sum(Y_train)


# In[ ]:



