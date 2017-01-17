#README
This is a Python implementation of Network Traffic Flow Generator and Feature Extractor. The main functionality of this code is : <br>
1. To identify the flows in the network traffic <br>
2. To extract features to characterize the Flows
<br>
## PREREQUISITES
1. GraphLab library should be installed. <a href = "https://turi.com/download/install-graphlab-create-command-line.html">Link to install graphlab </a> and <a href= "https://turi.com/download/academic.html">get the License Key</a>.<br>
2. TensorFlow should be installed.<br>
3. CSV Input file having the packets captured and the columns mentioned should be available using Wireshark.<br>
## INPUT
A CSV File of Network Traffic capture. It can be easily done using Wireshark, an Open Source tool. The following columns must be there in the CSV: <br>
     'Source',<br>
     'Source Port',<br>
     'Answer RRs',<br>
     'Destination',<br>
     'Destination Port',<br>
     'Protocol',<br>
     'Protocols in frame',<br>
     'Differentiated Services Field',<br>
     'Time',<br>
     'IP_Flags',<br>
     'Info',<br>
     'Length',<br>
     'Next sequence number',<br>
     'No.',<br>
     'Sequence number',<br>
     'TCP Segment Len',<br>
     'Time to live',<br>
     'tcp_Flags',<br>
     'udp_Length'
     
 ## ARGUMENTS
 It takes command line argument - the path of the CSV Input file described above.
 ## OUTPUT
 <p>A CSV File having all the flows and Flow based Features. </p>
 <p>This file can be further used to analyze properties and characteristics of the Network Traffic Captured</p>
 <p>List of Features Generated per flow: 
Source IP<br>
Destination IP<br>
Source port<br>
Destination port<br>
Protocol<br>
Total number of packets ex-changed<br>
Number of null packets ex-changed<br>
IOPR (ratio between the number of incoming packets over the number of outgoing packets)<br>
Reconnect (number of reconnects)<br>
Duration (flow duration)<br>
FPS (length of the first packet)<br>
Total number of bytes<br>
Average payload packet length<br>
Dotal number of packets with the same length over the total num-ber of packets<br>
Standard deviation of payload packet length<br>
Average bits-per-second<br>
Average packets-per-second in a time window<br>
Average inter arrival time of packets<br>
Average packets-per-second<br>
 </p>
 ## FUTURE WORK
 1. Automatically extract the CSV File from the pcap File of the captured traffic.<br>
 2. 
 
 
 
 
