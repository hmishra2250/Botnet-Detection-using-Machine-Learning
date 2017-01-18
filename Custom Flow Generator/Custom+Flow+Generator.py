
# coding: utf-8

# In[2]:
import sys
import graphlab as gl
import matplotlib.pyplot as plt

# Function to give unique id to every 5 tuple of Souce, Destination, Source Port, Destination Port and Protocol
def flow_id(x):
    if x['Source']>x['Destination']:
        return x['Source']+'-'+x['Destination']+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+x['Protocol']
    else:
        return x['Destination']+'-'+x['Source']+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+x['Protocol']
    

## function for comparing two different flows based on columns
def compareUF(x,y):
    if x!=y:
        return False
    return True

# Function to identify the unique Flow No. of every packet 
# Input : csv file of the packet capture, converted using Wireshark
def FlowIdentifier(filename):
    SF2 = gl.SFrame.read_csv(filename,verbose=False)
    print "Done reading"
    
    # Removing records not having Source or Destination Ports
    SF2 = SF2[(SF2['Source Port']!='')&(SF2['Destination Port']!='')]
    
    # Convert tcp Flags to integer, if present, else mark 0
    SF2['tcp_Flags'] = SF2['tcp_Flags'].apply(lambda x:int(x,16) if x!='' else 0)
    
    #For identifying IOPR feature, used later
    SF2['Forward'] = SF2.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )
    
    # Assign Flow ID based on the 5 tuple
    SF2['UFid'] = SF2.apply(lambda x:flow_id(x))
    
    
    
    ##Code for logic of Bidirectional flow identification


    FlowNo = 0 ##Unique Flow Number for each flow, assigned to every packet
    prev = None
    Flow = []     ##Stores all flows in form of list of dictionary 
    #cFlow = []    ##Store the current flow (all details)
    count = 0
    fc = 0
    startTime = None   ##Start Time of each flow to implement timeout
    
    # Sort the records based on the 5 tuple flow id and time, so that all packets corresponding to same 5 tuple are grouped together, making it easier for identifying the flows 
    SF2 = SF2.sort(['UFid','Time'])
    #print 'Done Sorting'
    
    # Now, we will label every packet with a unique flow no. to which it belongs
    for x in SF2:
        #if count%500000 == 0:
            #print 'Running '+str(count)+' Done !'

        count = count+1

        if prev is None:
            if startTime is None:
                #New Flow, record the start time and add to List of all flows
                startTime = x['Time']
            Flow.append(FlowNo)
            prev = x['UFid']
            
        elif compareUF(x['UFid'],prev):
            #Flow is already existing
            if x['tcp_Flags']&1:
                #Packet has a FIN Flag, terminate the flow including this as the last packet
                Flow.append(FlowNo)
                prev = None
                startTime = None
                FlowNo = FlowNo + 1

            elif x['Time']-startTime>=3600:
                # Duration of the flow crosses Timeout value, start a new flow with this as its first packet
                FlowNo = FlowNo + 1
                Flow.append(FlowNo)
                prev = None
                startTime = x['Time']

            else:
                # New packet in a pre-existing flow
                Flow.append(FlowNo)
                prev = x['UFid']

        else:
            # Previous Flow tuple didnt receive any more packets, start a new flow
            FlowNo = FlowNo + 1
            Flow.append(FlowNo)
            prev = x['UFid']
            startTime = x['Time']


    print len(gl.SArray(Flow).unique())


    SF2['Flow'] = gl.SArray(Flow)
    temp = SF2.groupby('Flow',{
                'Count':gl.aggregate.COUNT()
            })
    #len(temp[temp['Count']>1])

    SF2['FlowNo.'] = gl.SArray(Flow)

	# Output of this function : Packet wise Flow Number marked and stored as a csv file in the same folder.
	# This file will be used to generate the features
    SF2.save('Ports_Only_Sorted_Flow_BD.csv')




# Function to generate features Flow Wise

def Flow_Feature_Generator(packetcapturecsv):

	# Generate packet wise flow numbers
    FlowIdentifier(packetcapturecsv)
    SF2 = gl.SFrame.read_csv('Ports_Only_Sorted_Flow_BD.csv',verbose=False)
    
    ## FLOW BASED FEATURE GENERATION
    
    ## Ratio of incoming to outgoing packets
    temp = SF2.groupby('FlowNo.',{
            'NumForward' : gl.aggregate.SUM('Forward'),
            'Total' : gl.aggregate.COUNT()
        })
    temp['IOPR']= temp.apply(lambda x: ((x['Total']-x['NumForward'])*1.0)/x['NumForward'] if x['NumForward'] !=0 else (-1) )
    temp = temp['FlowNo.','IOPR']


    SF2 = SF2.join(temp,on='FlowNo.')
    del(temp)

    ## First Packet Length
    FlowFeatures = ['Source','Destination','Source Port','Destination Port','Protocol']
    FPL = SF2.groupby(['FlowNo.'],{
            'Time':gl.aggregate.MIN('Time')
        })
    #print len(FPL)
    FPL = FPL.join(SF2,on =['FlowNo.','Time'])[['FlowNo.','Length']].unique()
    FPL = FPL.groupby(['FlowNo.'],{
            'FPL':gl.aggregate.AVG('Length')
        })

    SF2 = SF2.join(FPL, on ='FlowNo.')
    del(FPL)


    # ## 18/10/2016


    ## Number of packets per flow
    temp = SF2.groupby(['FlowNo.'],{
            'NumPackets':gl.aggregate.COUNT()
        })
    #print temp.head(3)
    SF2 = SF2.join(temp, on ='FlowNo.')
    del(temp)


    ## Number of bytes exchanged
    temp = SF2.groupby(['FlowNo.'],{
            'BytesEx':gl.aggregate.SUM('Length')
        })
    SF2 = SF2.join(temp, on ='FlowNo.')
    del(temp)


    # In[38]:

    ## Standard deviation of packet length
    temp = SF2.groupby(['FlowNo.'],{
            'StdDevLen':gl.aggregate.STDV('Length')
        })
    SF2 = SF2.join(temp, on ='FlowNo.')
    del(temp)


    # In[40]:

    ## Same length packet ratio
    temp2 = SF2.groupby(['FlowNo.'],{
            'SameLenPktRatio':gl.aggregate.COUNT_DISTINCT('Length')
        })
    ##temp from number of packets computation
    temp = SF2.groupby(['FlowNo.'],{
            'NumPackets':gl.aggregate.COUNT()
        })
    temp = temp.join(temp2,on='FlowNo.')
    temp['SameLenPktRatio'] = temp['SameLenPktRatio']*1.0/temp['NumPackets']
    temp2 = None
    temp = temp[['FlowNo.','SameLenPktRatio']]
    SF2 = SF2.join(temp, on ='FlowNo.')

    del(temp)
    # In[41]:

    ## Duration of flow
    timeF = SF2.groupby(['FlowNo.'],{
            'startTime':gl.aggregate.MIN('Time'),
            'endTime':gl.aggregate.MAX('Time')
        })
    timeF['Duration'] = timeF['endTime'] - timeF['startTime']
    timeF = timeF[['FlowNo.','Duration']]
    SF2 = SF2.join(timeF, on ='FlowNo.')

    
    # In[45]:

    #sorted(SF2.column_names())


    # Relevant Features extracted till now

    features = ['Answer RRs',
     'BytesEx',
     'Destination',
     'Destination Port',
     'Differentiated Services Field',
     'Duration',
     'FPL',
     'IP_Flags',
     'Info',
     'Length',
     'Next sequence number',
     'No.',
     'NumPackets',
     'Protocol',
     'Protocols in frame',
     'SameLenPktRatio',
     'Sequence number',
     'Source',
     'Source Port',
     'StdDevLen',
     'TCP Segment Len',
     'Time',
     'Time to live',
     'tcp_Flags',
     'FlowNo.',
     'udp_Length',
     'IOPR']
    SF2 = SF2[features]


    # In[52]:

    ## Average packets per second
    temp =  SF2.groupby(['FlowNo.'],{
            'NumPackets':gl.aggregate.COUNT()
        })
    temp = temp.join(timeF,on=['FlowNo.'])
    temp['AvgPktPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['NumPackets']*1.0/x['Duration'])
    temp = temp[['FlowNo.','AvgPktPerSec']]
    SF2 = SF2.join(temp, on ='FlowNo.')

    del(temp)
    # In[53]:

    ##Average Bits Per Second
    temp = SF2.groupby(['FlowNo.'],{
            'BytesEx':gl.aggregate.SUM('Length')
        })
    temp = temp.join(timeF,on=['FlowNo.'])
    temp['BitsPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['BytesEx']*8.0/x['Duration'])
    temp = temp[['FlowNo.','BitsPerSec']]
    SF2 = SF2.join(temp, on ='FlowNo.')
    del(temp)

    # In[55]:

    ## Average Packet Lentgth
    temp = SF2.groupby(['FlowNo.'],{
            'APL':gl.aggregate.AVG('Length')
        })
    SF2 = SF2.join(temp, on ='FlowNo.')
    del(temp)

    # In[ ]:

    

    ## Inter arrival time of the packets
    SF2['IAT'] = 0
    SF2 = SF2.sort(['FlowNo.','Time'])
    prev = None
    prevT = None
    li = []
    for x in SF2:
        if prev is None or x['FlowNo.']!= prev:
            li.append(0)
        else:
            li.append(x['Time']-prevT)        
        prev = x['FlowNo.']
        prevT = x['Time']
    SF2['IAT'] = gl.SArray(li)



    # In[67]:

    #SF2.save('Bidirectional_Test_Bot_features_till_IAT.csv')


    # # Is Null feature

    # ### Number of TCP Null packets


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

    SF2['isNull'] = SF2.apply(lambda x:checkNull(x))
    NPEx = SF2.groupby(['FlowNo.'],{
            'NPEx':gl.aggregate.SUM('isNull')
        })
    SF2 = SF2.join(NPEx, on ='FlowNo.')

    del(NPEx)
    
    
    # ### Number of Reconnects - considering only TCP reconnects, using sequence number

    recon = SF2[SF2['Sequence number']!=''].groupby(['FlowNo.'],{
            'total_seq_no.' : gl.aggregate.COUNT('Sequence number'),
            'distinct_seq_no.' : gl.aggregate.COUNT_DISTINCT('Sequence number')
        })
    recon['reconnects'] = recon['total_seq_no.'] - recon['distinct_seq_no.']
    recon.head()
    recon = recon[['FlowNo.','reconnects']]
    SF2 = SF2.join(recon,on='FlowNo.',how='left')
    len(SF2)

    del(recon)
    # In[81]:

    #To identify records where reconnect check was not applied like UDP etc
    SF2.fillna('reconnects',-1)


    # A lot of these reconnects can be simple retransmissions - due to out of order/timeout etcb
    
    #Combine the features to flow based information
    
    SF2['Forward'] = SF2.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )
    temp = SF2.groupby('FlowNo.',{
            'NumForward' : gl.aggregate.SUM('Forward'),

        })

    SF2= SF2.join(temp,on='FlowNo.')
    
    del(temp)
    
    # Combine the packet level features to select only the FLOW BASED FEATURES
    SF2 = SF2.groupby('FlowNo.',{
            'Answer RRs': gl.aggregate.SELECT_ONE('Answer RRs'),
            'BytesEx' : gl.aggregate.SELECT_ONE('BytesEx'),
            'Destination' : gl.aggregate.SELECT_ONE('Destination'),
            'Destination Port' : gl.aggregate.SELECT_ONE('Destination Port'),
            'Differentiated Services Field' : gl.aggregate.SELECT_ONE('Differentiated Services Field'),
            'Duration' : gl.aggregate.SELECT_ONE('Duration'),
            'FPL' : gl.aggregate.SELECT_ONE('FPL'),
            'IP_Flags' : gl.aggregate.SELECT_ONE('IP_Flags'),
            'Info' : gl.aggregate.SELECT_ONE('Info'),
            'Length' : gl.aggregate.SELECT_ONE('Length'),
            'Next sequence number' : gl.aggregate.SELECT_ONE('Next sequence number'),
            'No.' : gl.aggregate.SELECT_ONE('No.'),
            'NumPackets' : gl.aggregate.SELECT_ONE('NumPackets'),
            'Protocol' : gl.aggregate.SELECT_ONE('Protocol'),
            'Protocols in frame' : gl.aggregate.SELECT_ONE('Protocols in frame'),
            'SameLenPktRatio' : gl.aggregate.SELECT_ONE('SameLenPktRatio'),
            'Sequence number' : gl.aggregate.SELECT_ONE('Sequence number'),
            'Source' : gl.aggregate.SELECT_ONE('Source'),
            'Source Port' : gl.aggregate.SELECT_ONE('Source Port'),
            'StdDevLen' : gl.aggregate.SELECT_ONE('StdDevLen'),
            'IAT' : gl.aggregate.SELECT_ONE('IAT'),
            'isNull' : gl.aggregate.SELECT_ONE('isNull'),
            'NPEx' : gl.aggregate.SELECT_ONE('NPEx'),
            'reconnects' : gl.aggregate.SELECT_ONE('reconnects'),
            'APL' : gl.aggregate.SELECT_ONE('APL'),
            'BitsPerSec' : gl.aggregate.SELECT_ONE('BitsPerSec'),
            'AvgPktPerSec' : gl.aggregate.SELECT_ONE('AvgPktPerSec'),
            'udp_Length' : gl.aggregate.SELECT_ONE('udp_Length'),
            'tcp_Flags' : gl.aggregate.SELECT_ONE('tcp_Flags'),
            'Time to live' : gl.aggregate.SELECT_ONE('Time to live'),
            'Time' : gl.aggregate.SELECT_ONE('Time'),
            'TCP Segment Len' : gl.aggregate.SELECT_ONE('TCP Segment Len'),
            'IOPR' : gl.aggregate.SELECT_ONE('IOPR'),
            'NumForward' : gl.aggregate.SELECT_ONE('NumForward')
        })


	# FINAL OUTPUT : A CSV File having all the flows and Extracted Flow Based Features
    SF2.save('Bidirectional_Botnet_all_features.csv')



# MAIN

# Access the Input CSV Packet file from command line argument

Flow_Feature_Generator(sys.argv[1])

