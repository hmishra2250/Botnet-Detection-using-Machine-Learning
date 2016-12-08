package iscx.cs.unb.ca.ifm.flowgen;

import iscx.cs.unb.ca.ifm.data.BasicFlow;
import iscx.cs.unb.ca.ifm.data.BasicPacketInfo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

public class FlowGenerator {

//	private String header = "Source IP, Source Port, Destination IP, Destination Port, Protocol, "
//			+ "Flow Duration, Flow packets, Forward Packets, Backward Packets, Flow Bytes/s, Flow Packets/s, "
//			+ "Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
//			+ "Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
//			+ "Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
//			+ "Active Mean, Active Std, Active Max, Active Min,"
//			+ "Idle Mean, Idle Std, Idle Max, Idle Min";
	
	private String timeBasedHeader = "Source IP, Source Port, Destination IP, Destination Port, Protocol, "
			+ "Flow Duration, Flow Bytes/s, Flow Packets/s, "
			+ "Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
			+ "Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
			+ "Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
			+ "Active Mean, Active Std, Active Max, Active Min,"
			+ "Idle Mean, Idle Std, Idle Max, Idle Min";	
	
	private HashMap<String,BasicFlow> currentFlows;
	private HashMap<Integer,BasicFlow> finishedFlows;
	
	boolean bidirectional;
	long    flowTimeOut;
	long    flowActivityTimeOut;
	int     finishedFlowCount;
	
	
	public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
		super();
		this.bidirectional = bidirectional;
		this.flowTimeOut = flowTimeout;
		this.flowActivityTimeOut = activityTimeout; 
		init();
	}		
	
	private void init(){
		currentFlows = new HashMap<String, BasicFlow>();
		finishedFlows = new HashMap<Integer, BasicFlow>();
		finishedFlowCount = 0;		
	}
	
    public void addPacket(BasicPacketInfo packet){
    	BasicFlow   flow;
    	long        currentTimestamp = packet.getTimeStamp();
    	
    	if(this.currentFlows.containsKey(packet.getFlowId())){
    		flow = this.currentFlows.get(packet.getFlowId());
    		// Flow finished due flowtimeout: 
    		// 1.- we move the flow to finished flow list
    		// 2.- we eliminate the flow from the current flow list
    		// 3.- we create a new flow with the packet-in-process
    		if((currentTimestamp -flow.getFlowStartTime())>flowTimeOut){
    			if(flow.packetCount()>1){
    				finishedFlows.put(getFlowCount(), flow);    				
    				//flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
    			}
    			currentFlows.remove(packet.getFlowId());    			
    			currentFlows.put(packet.getFlowId(), new BasicFlow(bidirectional,packet,flow.getSrc(),flow.getDst(),flow.getSrcPort(),flow.getDstPort()));
        	// Flow finished due FIN flag (tcp only):
    		// 1.- we add the packet-in-process to the flow (it is the last packet)
        	// 2.- we move the flow to finished flow list
        	// 3.- we eliminate the flow from the current flow list   			
    		}else if(packet.hasFlagFIN()){
    			flow.addPacket(packet);    			
    			finishedFlows.put(getFlowCount(), flow);
    			currentFlows.remove(packet.getFlowId());  
    		}else{
    			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
    			flow.addPacket(packet);
    			currentFlows.put(packet.getFlowId(), flow);
    		}
    	}else{
    		currentFlows.put(packet.getFlowId(), new BasicFlow(bidirectional,packet)); 		
    	}
    }
     
    
    public void dumpTimeBasedFeatures(String path, String filename){
    	BasicFlow   flow;
    	try {
    		System.out.println("TOTAL Flows: "+(finishedFlows.size()+currentFlows.size()));
    		FileOutputStream output = new FileOutputStream(new File(path+filename));    
    		
    		output.write((this.timeBasedHeader+"\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpTimeBasedFeatures()+"\n").getBytes());
			}
			Set<String> ckeys = currentFlows.keySet();   		
			for(String key:ckeys){
	    		flow = currentFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpTimeBasedFeatures()+"\n").getBytes());
			}			
			
			output.flush();
			output.close();			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

    }      
    
    public int dumpLabeledTimeBasedFeatures(String path, String filename){
    	BasicFlow   flow;
    	String      label;
    	int         total = 0;
    	try {
    		total = finishedFlows.size()+currentFlows.size();
    		System.out.println("TOTAL Flows: "+total);
    		FileOutputStream output = new FileOutputStream(new File(path+filename));    
    		label = filename.split("_")[0];
    		
    		output.write((this.timeBasedHeader+",label\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpTimeBasedFeatures()+","+label+"\n").getBytes());
			}
			Set<String> ckeys = currentFlows.keySet();   		
			for(String key:ckeys){
	    		flow = currentFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpTimeBasedFeatures()+","+label+"\n").getBytes());
			}			
			
			output.flush();
			output.close();			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
        return total;
    }       
    
    private int getFlowCount(){
    	this.finishedFlowCount++;
    	return this.finishedFlowCount;
    }
}
