package iscx.cs.unb.ca.ifm.data;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

public class BasicFlow {
	private List<BasicPacketInfo> forward = null;
	private List<BasicPacketInfo> backward = null;
	
	private long forwardBytes;
	private long backwardBytes;
	
	private boolean isBidirectional;
	
	private    byte[] src;
    private    byte[] dst;
    private    int    srcPort;
    private    int    dstPort;
    private    int    protocol;
    private    long   flowStartTime;
    private    long   startActiveTime;
    private    long   endActiveTime;
    private    String flowId = null;    
    
    private    SummaryStatistics flowIAT = null;
    private    SummaryStatistics forwardIAT = null;
    private    SummaryStatistics backwardIAT = null;
    
    private    SummaryStatistics flowActive = null;
    private    SummaryStatistics flowIdle = null;
   // private    long              lastActivity;
    
    private    long   flowLastSeen;
    private    long   forwardLastSeen;
    private    long   backwardLastSeen;
    

	public BasicFlow(boolean isBidirectional,BasicPacketInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort, int flowDstPort) {
		super();
		this.initParameters();
		this.isBidirectional = isBidirectional;
		this.firstPacket(packet);
		this.src = flowSrc;
		this.dst = flowDst;
		this.srcPort = flowSrcPort;
		this.dstPort = flowDstPort;
	}    
    
	public BasicFlow(boolean isBidirectional,BasicPacketInfo packet) {
		super();
		this.initParameters();
		this.isBidirectional = isBidirectional;
		this.firstPacket(packet);
	}

	public BasicFlow(BasicPacketInfo packet) {
		super();
		this.initParameters();
		this.isBidirectional = true;		
		firstPacket(packet);
	}
	
	public void initParameters(){
		this.forward = new ArrayList<BasicPacketInfo>();
		this.backward = new ArrayList<BasicPacketInfo>();
		this.flowIAT = new SummaryStatistics();
		this.forwardIAT = new SummaryStatistics();
		this.backwardIAT = new SummaryStatistics();
		this.flowActive = new SummaryStatistics();
		this.flowIdle = new SummaryStatistics();
		this.forwardBytes = 0L;
		this.backwardBytes = 0L;	
		this.startActiveTime = 0L;
		this.endActiveTime = 0L;
		this.src = null;
		this.dst = null;
	}
	
	
	public void firstPacket(BasicPacketInfo packet){
		this.flowStartTime = packet.getTimeStamp();
		this.flowLastSeen = packet.getTimeStamp();
		this.startActiveTime = packet.getTimeStamp();
		this.endActiveTime = packet.getTimeStamp();
		
		if(this.src==null){
			this.src = packet.getSrc();
			this.srcPort = packet.getSrcPort();
		}
		if(this.dst==null){
			this.dst = packet.getDst();
			this.dstPort = packet.getDstPort();
		}		
		if(packet.isForwardPacket(this.src)){
			this.forwardLastSeen = packet.getTimeStamp();
			this.forwardBytes+=packet.getPayloadBytes();
			this.forward.add(packet);			
		}else{
			this.backwardLastSeen = packet.getTimeStamp();
			this.backwardBytes+=packet.getPayloadBytes();
			this.backward.add(packet);			
		}
		this.protocol = packet.getProtocol();
		this.flowId = packet.getFlowId();		
	}
    
    public void addPacket(BasicPacketInfo packet){
    	long currentTimestamp = packet.getTimeStamp();
    	if(isBidirectional){
    		if(packet.isForwardPacket(this.src)){
    			this.forward.add(packet);   
    			this.forwardBytes+=packet.getPayloadBytes();
    			if (this.forward.size()>1)
    				this.forwardIAT.addValue(currentTimestamp -this.forwardLastSeen);
    			this.forwardLastSeen = currentTimestamp;
    		}else{
    			this.backward.add(packet);
    			this.backwardBytes+=packet.getPayloadBytes();
    			if (this.backward.size()>1)
    				this.backwardIAT.addValue(currentTimestamp-this.backwardLastSeen);
    			this.backwardLastSeen = currentTimestamp;
    		}
    	}else{
    		this.forward.add(packet);    		
    		this.forwardBytes+=packet.getPayloadBytes();
    		this.forwardIAT.addValue(currentTimestamp-this.forwardLastSeen);
    		this.forwardLastSeen = currentTimestamp;
    	}
    	this.flowIAT.addValue(packet.getTimeStamp()-this.flowLastSeen);
    	this.flowLastSeen = packet.getTimeStamp();
    	
    }      
    
    public void updateActiveIdleTime(long currentTime, long threshold){
    	if ((currentTime - this.endActiveTime) > threshold){
    		if((this.endActiveTime - this.startActiveTime) > 0){
	      		this.flowActive.addValue(this.endActiveTime - this.startActiveTime);	      		
    		}
    		this.flowIdle.addValue(currentTime - this.endActiveTime);
    		this.startActiveTime = currentTime;
    		this.endActiveTime = currentTime;
    	}else{
    		this.endActiveTime = currentTime;
    	}
    }
    
    public void endActiveIdleTime(long currentTime, long threshold, long flowTimeOut, boolean isFlagEnd){
		
    	if((this.endActiveTime - this.startActiveTime) > 0){
      		this.flowActive.addValue(this.endActiveTime - this.startActiveTime);	      		
		}
    	
    	if (!isFlagEnd && ((flowTimeOut - (this.endActiveTime-this.flowStartTime))>0)){
    		this.flowIdle.addValue(flowTimeOut - (this.endActiveTime-this.flowStartTime));
    	}
    }    

    public String dumpTimeBasedFeatures(){
    	String dump = "";
    	dump+=FormatUtils.ip(src)+",";
    	dump+=getSrcPort()+",";
    	dump+=FormatUtils.ip(dst)+",";    			
    	dump+=getDstPort()+",";
    	dump+=getProtocol()+","; 
    	long flowDuration = this.flowLastSeen - this.flowStartTime; 
    	dump+=flowDuration+",";
    	// flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
    	dump+=((double)(this.forwardBytes+this.backwardBytes))/((double)flowDuration/1000000L)+",";    			
    	dump+=((double)packetCount())/((double)flowDuration/1000000L)+",";
    	dump+=this.flowIAT.getMean()+",";
    	dump+=this.flowIAT.getStandardDeviation()+",";
    	dump+=this.flowIAT.getMax()+",";
    	dump+=this.flowIAT.getMin()+",";    	
    	if(this.forward.size()>1){
        	dump+=this.forwardIAT.getMean()+",";
        	dump+=this.forwardIAT.getStandardDeviation()+",";
        	dump+=this.forwardIAT.getMax()+",";
        	dump+=this.forwardIAT.getMin()+",";
    	}else{
    		dump+="0,0,0,0,";
    	}
    	if(this.backward.size()>1){
        	dump+=this.backwardIAT.getMean()+",";
        	dump+=this.backwardIAT.getStandardDeviation()+",";
        	dump+=this.backwardIAT.getMax()+",";
        	dump+=this.backwardIAT.getMin()+","; 
    	}else{
    		dump+="0,0,0,0,";
    	}    	   	 
    	if(this.flowActive.getN()>0){
        	dump+=this.flowActive.getMean()+",";
        	dump+=this.flowActive.getStandardDeviation()+",";
        	dump+=this.flowActive.getMax()+",";
        	dump+=this.flowActive.getMin()+",";  
    	}else{
    		dump+="0,0,0,0,";
    	}    	
    	
    	if(this.flowIdle.getN()>0){
	    	dump+=this.flowIdle.getMean()+",";
	    	dump+=this.flowIdle.getStandardDeviation()+",";
	    	dump+=this.flowIdle.getMax()+",";
	    	dump+=this.flowIdle.getMin();    
    	}else{
    		dump+="0,0,0,0";
    	}
    	
    	return dump;
    }      
    
    public int packetCount(){
    	if(isBidirectional){
    		return (this.forward.size() + this.backward.size()); 
    	}else{
    		return this.forward.size();    		
    	}
    }
    
	public List<BasicPacketInfo> getForward() {
		return forward;
	}

	public void setForward(List<BasicPacketInfo> forward) {
		this.forward = forward;
	}

	public List<BasicPacketInfo> getBackward() {
		return backward;
	}

	public void setBackward(List<BasicPacketInfo> backward) {
		this.backward = backward;
	}

	public boolean isBidirectional() {
		return isBidirectional;
	}

	public void setBidirectional(boolean isBidirectional) {
		this.isBidirectional = isBidirectional;
	}

	public byte[] getSrc() {
		return src;
	}

	public void setSrc(byte[] src) {
		this.src = src;
	}

	public byte[] getDst() {
		return dst;
	}

	public void setDst(byte[] dst) {
		this.dst = dst;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public int getProtocol() {
		return protocol;
	}
	
	public String getProtocolStr() {
		switch(this.protocol){
		case(6):
			return "TCP";
		case(17):
		    return "UDP";
		}
		return "UNKNOWN";
	}	

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public long getFlowStartTime() {
		return flowStartTime;
	}

	public void setFlowStartTime(long flowStartTime) {
		this.flowStartTime = flowStartTime;
	}

	public String getFlowId() {
		return flowId;
	}

	public void setFlowId(String flowId) {
		this.flowId = flowId;
	}

	public long getLastSeen() {
		return flowLastSeen;
	}

	public void setLastSeen(long lastSeen) {
		this.flowLastSeen = lastSeen;
	}

	public long getStartActiveTime() {
		return startActiveTime;
	}

	public void setStartActiveTime(long startActiveTime) {
		this.startActiveTime = startActiveTime;
	}

	public long getEndActiveTime() {
		return endActiveTime;
	}

	public void setEndActiveTime(long endActiveTime) {
		this.endActiveTime = endActiveTime;
	}
		
}
