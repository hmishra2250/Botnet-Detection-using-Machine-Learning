# -*- coding: utf-8 -*-
# <nbformat>3.0</nbformat>

# <codecell>

import pandas as pd
import numpy as np
import collections as coll

# <codecell>

df2 = pd.read_csv('/home/kartik/Downloads/iscx-part175.csv')
df2['StartTime'] = pd.Series(0.0,index=df2.index)
df2['EndTime'] = pd.Series(0.0,index=df2.index)
df2['TotalNumBytes'] = pd.Series(0,index=df2.index)
df2['NumPacketsExchg'] = pd.Series(0,index=df2.index)

# <codecell>

ipPort = ''

# will have all timestamped final value flows
#i=0

currFlowFeatures = coll.defaultdict(list)
overallFlowFeatures = coll.defaultdict(list)
currFlowPackets = {}
# will have most recent timestamp flow
    
currFlowStartTime = {}
    

# <codecell>

def storeFlows(row):
    ipPort = row['Source'] + str(row['SourcePort']) + row['Destination'] + str(row['DestPort'])
    i=0
    #ipTime = str(row['Time']) + ipPort
    #if(row['Flags']==''):
     #   continue
    try:
        if int(row['Flags'],16) & 2 is not 0:
            currFlowFeatures[ipPort]= [row['Time'], -1 ,0 ,0]
            
        
        if len(currFlowFeatures[ipPort]) == 0:
            currFlowFeatures[ipPort]= [row['Time'], -1 ,0 ,0]
            
        
        currFlowFeatures[ipPort][2] = currFlowFeatures[ipPort][2] + 1
        currFlowFeatures[ipPort][3] = currFlowFeatures[ipPort][3] + row['Length']
    
        if (int(row['Flags'],16) & 1 is not 0) or (row['Time']-currFlowFeatures[ipPort][0])>72:
            ipTime = ipPort + str(currFlowFeatures[ipPort][0])
            currFlowFeatures[ipPort][1] = row['Time']
            overallFlowFeatures[ipTime] = currFlowFeatures[ipPort]
            currFlowFeatures[ipPort]=[]
            
            
    except TypeError:
        i = i +1

# <codecell>

def updateDf(row,h1,h2,h3,h4):
    i =0 
    
        
    ipPort = row['Source'] + str(row['SourcePort']) + row['Destination'] + str(row['DestPort'])
    
   
    try:
        if int(row['Flags'],16) & 2 is not 0:
            currFlowPackets[ipPort] = 0
            currFlowStartTime[ipPort] = row['Time']
            
    
        currFlowPackets[ipPort] = currFlowPackets.get(ipPort,0) + 1
        if(currFlowPackets[ipPort]==1):
            currFlowStartTime[ipPort] = row['Time']
        
        ipTime = ipPort + str(currFlowStartTime[ipPort])
        try:
            if(len(overallFlowFeatures[ipTime]) > 0):
                #df2.set_value(index,'StartTime',overallFlowFeatures[ipTime][0])
                #print overallFlowFeatures[ipTime][0]
                #df2.set_value(index,'EndTime',overallFlowFeatures[ipTime][1])
                #df2.set_value(index,'TotalNumBytes',overallFlowFeatures[ipTime][2])
                #df2.set_value(index,'NumPacketsExchg',overallFlowFeatures[ipTime][3])
                return pd.Series({h1:overallFlowFeatures[ipTime][0],h2:overallFlowFeatures[ipTime][1],h3:overallFlowFeatures[ipTime][2],h4:overallFlowFeatures[ipTime][3]})
            
        except IndexError:
            print ipTime
        
        
            
    except TypeError:
        i = i +1
    
        
    


# <codecell>

timeit df2.apply(lambda s: storeFlows(s),axis=1)

# <codecell>

df2.apply(lambda s: updateDf(s,'StartTime','EndTime','TotalNumBytes','NumPacketsExchg'),axis=1)

# <codecell>


