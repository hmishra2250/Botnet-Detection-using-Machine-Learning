
# coding: utf-8

# In[1]:

import graphlab as gl
import tensorflow as tf


# In[2]:

SF = gl.SFrame.read_csv('ISCX_Botnet-Testing_Ports_Only.csv')


# In[ ]:

#SF.head(5)


# In[ ]:

#SF.column_names()


# In[ ]:

SF = SF[(SF['Source Port']!='')|(SF['Destination Port']!='')]


# In[ ]:



# In[ ]:


# In[ ]:

#type(SF['tcp_Flags'][0])


# In[ ]:

#SF['tcp_Flags'].unique()


# In[ ]:

#SF['IP_Flags'].unique()


# In[ ]:

SF['tcp_Flags'] = SF['tcp_Flags'].apply(lambda x:int(x,16) if x!='' else 0)


# In[ ]:



# In[ ]:

##Testing code for time comparison in iteration
"""import time
start = time.time()
for i in SF:
    i['tcp_Flags']
print time.time()-start"""


# In[ ]:


# In[ ]:

#print lt,"\n\n",gt


# In[ ]:

#print len(lt),len(gt)


# In[ ]:



sorting_features = ['Source','Destination','Source Port','Destination Port','Protocol','Time']
#STD = SF[['No.','Time','Source','Destination','Source Port','Destination Port','Protocol','tcp_Flags']]
#STD = STD.sort(sorting_features)
#print 'Done sorting STD'
SF = SF.sort(sorting_features)
print 'Done sorting SF'


# In[ ]:

#STD.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow.csv')
#print 'Done saving STD'
#STD = None


# In[ ]:

#STD = None
SF.head(3)


# In[ ]:

type(SF['Time'][0])


# In[ ]:

SF['tcp_Flags'].unique()


# ### Checking if No. is the unique primary key for data for

# In[ ]:

print len(SF),len(SF['No.'].unique())


# ## Back to flow identification 

# In[ ]:

## function for comparing two different flows based on columns
def compare(x,y,columns):
    try:
        val = True
        for column in columns:
            if x[column]!=y[column]:
                val = False
                break;
        return val
    except KeyError:
        print "Column does not exist in the data, check again!"
    except:
        print "Some unknown error"


# In[ ]:

##Code for logic of flow identification
import pickle 

FlowCols = ['Source','Destination','Source Port','Destination Port','Protocol']
SF['FlowNo.'] = None
FlowNo = 0 ##Unique Flow Number for each flow
#FFlow = []
prev = None
Flow = []     ##Stores all flows in form of list of dictionary 
#cFlow = []    ##Store the current flow (all details)
count = 0
fc = 0
startTime = None   ##Start Time of each flow to implement timeout
for x in SF:
    if count%500000 == 0:
        #fName = 'Flow'+str(fc)+'.pkl'
        #print 'Saving : ',fName
        #pickle.dump(Flow,open(fName,'w'))
        #print 'Saved'
        print 'Running '+str(count)+' Done !'
        #c = fc + 1
        #Flow = []
    count = count+1
    
    if prev is None:
        if startTime is None:
            startTime = x['Time']
        Flow.append(FlowNo)
        
        #cFlow.append(x['No.'])
        
        prev = x
    elif compare(x,prev,FlowCols):
        if x['tcp_Flags']&1 or x['tcp_Flags']&4:
            Flow.append(FlowNo)
            prev = None
            startTime = None
            FlowNo = FlowNo + 1
            
            #cFlow.append(x['No.'])
            #FFlow.append(cFlow)
            #cFlow = []
            
        elif x['Time']-startTime>=120 or x['Time']-prev['Time']>=5:
            FlowNo = FlowNo + 1
            Flow.append(FlowNo)
            prev = None
            startTime = x['Time']
            
            
        else:
            
            #cFlow.append(x['No.'])
            
            Flow.append(FlowNo)
            prev = x
    else:
        FlowNo = FlowNo + 1
        Flow.append(FlowNo)
        
        #FFlow.append(cFlow)
        #cFlow = []
        #cFlow.append(x['No.'])
        
        prev = x
        startTime = x['Time']


print len(gl.SArray(Flow).unique())


# In[ ]:

len(Flow)


# In[ ]:

len(SF)


# In[ ]:

SF['FlowNo.'] = gl.SArray(Flow)


# In[ ]:

##Code for checking authenticity of flow logic
#STD[(STD['Source']=='0.0.0.0')&(STD['Destination']=='255.255.255.255')&(STD['Source Port']=='68')&(STD['Destination Port']=='67')].sort('Time')


# In[ ]:

## Code to check if in any flows there are some No.s which are in decreasing order (Indicative or Decrepancies)
## UPDATE: No. does not indicate same relation in time, so Data collected is right !
"""count = 0
for li in Flow:
    for i in range(1,len(li)):
        if li[i]<li[i-1]:
            #print li
            count = count+1
            break;
print count"""


# In[ ]:

import pickle
pickle.dump(Flow,open('Flow.pkl','w'))


# In[ ]:

SF.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow.csv')


# In[ ]:

SF.head(3)


# In[ ]:

## First Packet Length
FlowFeatures = ['Source','Destination','Source Port','Destination Port','Protocol']
FPL = SF.groupby(['FlowNo.'],{
        'Time':gl.aggregate.MIN('Time')
    })
print len(FPL)
FPL = FPL.join(SF,on =['FlowNo.','Time'])[['FlowNo.','Length']].unique()
FPL = FPL.groupby(['FlowNo.'],{
        'Length':gl.aggregate.AVG('Length')
    })
print len(FPL)


# In[ ]:

FPL.save('FirstPacketLength.csv')


# ## 18/10/2016

# In[ ]:

import graphlab as gl
import tensorflow as tf


# In[ ]:

SF = gl.SFrame.read_csv('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow.csv',verbose=False)


# In[ ]:

## Number of packets per flow
temp = SF.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
print temp.head(3)
temp.save('NumPacketsPerFlow.csv')


# In[ ]:

## Number of bytes exchanged
temp = SF.groupby(['FlowNo.'],{
        'BytesEx':gl.aggregate.SUM('Length')
    })
temp.save('BytexExchangedPerFlow.csv')
temp.head(3)


# In[ ]:

## Standard deviation of packet length
temp = SF.groupby(['FlowNo.'],{
        'StdDevLen':gl.aggregate.STDV('Length')
    })
temp.save('StdDevLenPerFlow.csv')
temp.sort('StdDevLen')[-10:]


# In[ ]:

## Same length packet ratio
temp2 = SF.groupby(['FlowNo.'],{
        'SameLenPktRatio':gl.aggregate.COUNT_DISTINCT('Length')
    })
##temp from number of packets computation
temp = SF.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
temp = temp.join(temp2,on='FlowNo.')
temp['SameLenPktRatio'] = temp['SameLenPktRatio']*1.0/temp['NumPackets']
temp2 = None
temp = temp[['FlowNo.','SameLenPktRatio']]
temp.save('SameLenPktRatio.csv')
temp.head(3)


# In[ ]:

def tfn(x):
    if 'udp' in x.split(':'):
        return 1
    return 0
SF['hasUDP'] = SF['Protocols in frame'].apply(lambda x:tfn(x))


# In[ ]:

test = SF[SF['hasUDP']==1]
test['colDiff'] = test['Length'] - test['udp_Length']
test[test['colDiff']==-1].head(3)


# In[ ]:

test[test['colDiff']<-20].head(3)


# In[ ]:

## Duration of flow
timeF = SF.groupby(['FlowNo.'],{
        'startTime':gl.aggregate.MIN('Time'),
        'endTime':gl.aggregate.MAX('Time')
    })
timeF['Duration'] = timeF['endTime'] - timeF['startTime']
timeF[['FlowNo.','Duration']].save('DurationFlow.csv')
timeF = timeF[['FlowNo.','Duration']]


# In[ ]:

## Average packets per second
temp = gl.SFrame.read_csv('NumPacketsPerFlow.csv',verbose=False)
temp = temp.join(timeF,on=['FlowNo.'])
temp['AvgPktPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['NumPackets']*1.0/x['Duration'])
temp = temp[['FlowNo.','AvgPktPerSec']]
temp.save('AvgPktPerSecFlow.csv')
temp.sort('AvgPktPerSec')[-10:]


# In[ ]:

##Average Bits Per Second
temp = gl.SFrame.read_csv('BytexExchangedPerFlow.csv',verbose=False)
temp = temp.join(timeF,on=['FlowNo.'])
temp['BitsPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['BytesEx']*8.0/x['Duration'])
temp = temp[['FlowNo.','BitsPerSec']]
temp.save('BitsPerSecPerFlow.csv')
temp.sort('BitsPerSec')[-5:]


# In[ ]:

## Average Packet Lentgth
temp = SF.groupby(['FlowNo.'],{
        'APL':gl.aggregate.AVG('Length')
    })
temp.save('AveragePktLengthFlow.csv')


# In[ ]:

test = SF[SF['hasUDP']==1]
test['colDiff'] = test['Length'] - test['udp_Length']
len(test[test['colDiff']<0])


# In[ ]:

len(test)


# In[ ]:

## Number of Reconnects, sort FlowNo, SeqNo


# In[ ]:

def tfn(x):
    if 'udp' in x.split(':') or 'tcp' in x.split(':'):
        return 1
    return 0
temp = list(SF['Protocols in frame'].apply(lambda x:tfn(x)))


# In[ ]:

len(temp)


# In[ ]:

sum(temp)


# In[ ]:

SF.head(1)


# In[ ]:

type(SF['TCP Segment Len'][0])


# In[ ]:

type(SF['udp_Length'][0])


# In[ ]:

len(SF[(SF['udp_Length'] == None)&(SF['TCP Segment Len'] == '')])


# In[ ]:

SF[(SF['udp_Length'] == None)&(SF['TCP Segment Len'] == '')]['Protocols in frame'].unique()


# In[ ]:

print len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:urlencoded-form']),len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp']),len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:data'])


# In[ ]:

## Inter arrival time
SF['IAT'] = 0
SF = SF.sort(['FlowNo.','Time'])
prev = None
prevT = None
li = []
for x in SF:
    if prev is None or x['FlowNo.']!= prev:
        li.append(0)
    else:
        li.append(x['Time']-prevT)        
    prev = x['FlowNo.']
    prevT = x['Time']
SF['IAT'] = gl.SArray(li)


# In[ ]:

SF.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow_IAT.csv')


# In[ ]:

SF.head(3)


# In[ ]:

#len(SF[(SF['udp_Length']>=8)&(SF['udp_Length']<=16)])


# In[ ]:

#print len(SF[SF['udp_Length']==8])
#print len(SF[SF['udp_Length']==16])


# In[ ]:

#SF[SF['Protocols in frame']=='eth:llc:ipx'].head(3)


# In[ ]:

#SF[SF['Protocols in frame']=='eth:ethertype:ipx'].head(3)


# In[ ]:

#print len(SF[SF['Protocols in frame']=='eth:ipx'])


# In[ ]:

#SF[SF['udp_Length']==0]


# In[ ]:

print len(SF[SF['Protocols in frame']=='eth:ipx'])


# In[ ]:

SF[SF['hasUDP']==1]['Protocols in frame'].unique()


# # Is Null feature

# ### Number of TCP Null packets

# In[ ]:

len(SF[SF['Protocol']=='TCP'])


# ### Number of UDP NUll Packets

# In[ ]:

len(SF[SF['udp_Length']==8]), len(SF[SF['Protocol']=='UDP'])


# In[ ]:

SF[SF['TCP Segment Len']=='0']['Protocols in frame'].unique()


# ### Null Packets exchanged,
# TCP -> tcp segment len =0,
# UDP -> udp len = 8,
# non tcp udp -> length - individual headers

# In[ ]:

tt = SF[(SF['TCP Segment Len']!='0')&(SF['udp_Length']!=8 )]


# In[ ]:

len(tt)


# In[ ]:

## Null Packets handling
def checkNull(x):
    if(x['TCP Segment Len']=='0' or x['udp_Length']==8 ):
        return 1
    elif('ipx' in x['Protocols in frame'].split(':')):
        l = x['Length'] - 30
        if('eth' in x['Protocols in frame'].split(':')):
            l = l - 14
        if('ethtype' in x['Protocols in frame'].split(':')):
            l = l - 2
        if('llc' in x['Protocols in frame'].split(':')):
            l = l - 8
        if(l==0 or l==-1):
            return 1
    return 0


# In[ ]:

SF['isNull'] = SF.apply(lambda x:checkNull(x))


# In[ ]:

len(SF[SF['isNull']==1])


# In[ ]:

NPEx = SF.groupby(['FlowNo.'],{
        'NPEx':gl.aggregate.SUM('isNull')
    })
NPEx.save('NumberNullPacketsEXc.csv')


# ### Number of Reconnects - considering only TCP reconnects, using sequence number

# In[ ]:

type(SF['Sequence number'][0])


# In[ ]:

recon = SF[SF['Sequence number']!=''].groupby(['FlowNo.'],{
        'total_seq_no.' : gl.aggregate.COUNT('Sequence number'),
        'distinct_seq_no.' : gl.aggregate.COUNT_DISTINCT('Sequence number')
    })
recon['reconnects'] = recon['total_seq_no.'] - recon['distinct_seq_no.']
recon.head()
recon[['FlowNo.','reconnects']].save('ReconnectsFlow.csv')


# In[ ]:

#SF[SF['FlowNo.']==79732]['Info']


# A lot of these reconnects can be simple retransmissions - due to out of order/timeout etcb

# In[74]:

## Ratio of incoming to outgoing packets

"""convo = SF.groupby(['FlowNo.'],{
        'start_time': gl.aggregate.MIN('Time'),
        'protocol':gl.aggregate.SELECT_ONE('Protocol'),
        'src_ip': gl.aggregate.SELECT_ONE('Source'),
        'dst_ip': gl.aggregate.SELECT_ONE('Destination'),
        'src_port': gl.aggregate.SELECT_ONE('Source Port'),
        'dst_port': gl.aggregate.SELECT_ONE('Destination Port')
    })
convo.sort('start_time')


# In[53]:

convo['rev_flow_no.'] = -1
convo.head()


# for x in convo:
#     if x['rev_flow_no.']==-1:
#         for y in convo:
#             if y['rev_flow_no.']==-1 & (x['src_ip']==y['dst_ip']) & (x['src_port']==y['dst_port']) & (y['src_ip']==x['dst_ip']) &(y['src_port']==x['dst_port']) & (x['protocol']==y['protocol']) :
#                 x['rev_flow_no.'] = y['FlowNo.']
#                 y['rev_flow_no.'] = x['FlowNo.']
#                 break
#             if y['start_time']-x['start_time'] > 100 :
#                 break

# In[71]:

temp1 = convo
temp1.rename({'src_ip':'dst_ip1', 'src_port':'dst_port1'})
temp1.rename({'dst_ip':'src_ip','dst_port':'src_port'})
temp1.rename({'dst_ip1':'dst_ip', 'dst_port1':'dst_port'})
temp1.rename({'start_time':'return_time'})
temp1.rename({'FlowNo.':'rev_flow'})


# In[73]:


temp1 = temp1['src_ip','dst_ip','src_port','dst_port','protocol','return_time','rev_flow'] 


# In[ ]:

convo = SF.groupby(['FlowNo.'],{
        'start_time': gl.aggregate.MIN('Time'),
        'protocol':gl.aggregate.SELECT_ONE('Protocol'),
        'src_ip': gl.aggregate.SELECT_ONE('Source'),
        'dst_ip': gl.aggregate.SELECT_ONE('Destination'),
        'src_port': gl.aggregate.SELECT_ONE('Source Port'),
        'dst_port': gl.aggregate.SELECT_ONE('Destination Port')
    })
convo.sort('start_time')


# In[77]:

temp2 = temp1.join(convo,on=['src_ip','dst_ip','src_port','dst_port','protocol'])


# In[78]:


temp2


# In[79]:

convo


# In[82]:

temp1[(temp1['src_ip']=='66.249.73.56') & (temp1['src_port']==52954)]


# In[83]:

temp2['reply_time'] = temp2['return_time'] - temp2['start_time']
temp2.head()


# In[85]:

temp2['reply_time'].unique()


# In[88]:

len(temp2[(temp2['reply_time']<100) & (temp2['reply_time']>-100)])


# In[92]:

temp3 = temp2[(temp2['reply_time']<100) & (temp2['reply_time']>-100)]
temp4 = temp3.groupby(['src_ip','dst_ip','src_port','dst_port','protocol','start_time','FlowNo.'],{
        'rep_time': gl.aggregate.MIN('reply_time'),
        'rev_flow_no.' : gl.aggregate.ARGMIN('reply_time','rev_flow')
    })


# In[93]:

temp4.head()


# In[101]:

temp =  gl.SFrame.read_csv('NumPacketsPerFlow.csv',verbose=False)
temp2 = temp.join(temp4,on=['FlowNo.'])
temp.rename({'FlowNo.':'rev_flow_no.'})
temp2 = temp.join(temp2,on=['rev_flow_no.'])
temp2


# In[102]:

temp2['IOPR'] = temp2.apply(lambda x:0.0 if x['NumPackets'] == 0 else x['NumPackets.1']/x['NumPackets'])
temp2 = temp2[['FlowNo.','IOPR']]
temp2.save('IOPR.csv')
temp2.sort('IOPR')[-10:]


# In[108]:

SF.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow_IAT_Null.csv')


# ### 22-10-2016

# In[1]:

import graphlab as gl
import tensorflow as tf
SF = gl.SFrame.read_csv('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow_IAT_Null.csv',verbose=False)


# In[2]:

SF.head(3)


# In[4]:

len(SF[SF['Source']=='10.37.130.4'])


# In[5]:

len(SF[SF['Destination']=='10.37.130.4'])


# In[6]:

len(SF[SF['Source']=='10.37.130.4']['FlowNo.'].unique())


# In[7]:

len(SF['FlowNo.'].unique())


# In[9]:

len(SF[SF['Source']=='147.32.84.140']['FlowNo.'].unique())


# In[10]:

SF.head()


# In[11]:

Flows = gl.SFrame.read_csv('DurationFlow.csv')


# In[12]:

Flows['Duration'].unique()


# In[13]:

Flows.groupby(['Duration'],{
        'count':gl.aggregate.COUNT()
    })


# In[15]:

print min(SF['Time']),max(SF['Time'])


# In[ ]:
"""


