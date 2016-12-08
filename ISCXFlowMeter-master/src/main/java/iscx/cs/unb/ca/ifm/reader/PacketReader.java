package iscx.cs.unb.ca.ifm.reader;

import iscx.cs.unb.ca.ifm.data.BasicPacketInfo;
import iscx.cs.unb.ca.ifm.utils.IdGenerator;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import org.xml.sax.Attributes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;

public class PacketReader {
	private static final Logger logger = LogManager.getLogger();
	private IdGenerator  generator = new IdGenerator();
	private Pcap pcapReader;
	
	private long firstPacket;
	private long lastPacket;
	
	private Tcp  tcp;
	private Udp  udp;
	private Ip4  ipv4;
	private Ip6  ipv6;
	private L2TP l2tp;
	private PcapHeader hdr;
	private JBuffer buf;
	
	private boolean readIP6;
	private boolean readIP4;			
	
	public PacketReader(String filename) {
		super();	
		this.readIP4 = true;
		this.readIP6 = false;		
		this.config(filename);
	}
	
	public PacketReader(String filename, boolean readip4, boolean readip6) {
		super();	
		this.readIP4 = readip4;
		this.readIP6 = readip6;
		this.config(filename);
	}	
	
	private void config(String filename){
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		pcapReader = Pcap.openOffline(filename, errbuf);
		
		this.firstPacket = 0L;
		this.lastPacket = 0L;

		if (pcapReader == null) {
			logger.error("Error while opening file for capture: "+errbuf.toString());
			System.exit(-1);
		}else{
			this.tcp = new Tcp();
			this.udp = new Udp();
			this.ipv4 = new Ip4();
			this.ipv6 = new Ip6();
			this.l2tp = new L2TP();
			hdr = new PcapHeader(JMemory.POINTER);
			buf = new JBuffer(JMemory.POINTER);		
		}		
	}
	
	public BasicPacketInfo nextPacket(){
		 PcapPacket      packet;
		 BasicPacketInfo packetInfo = null;
		 try{
			 if(pcapReader.nextEx(hdr,buf) == Pcap.NEXT_EX_OK){
				 packet = new PcapPacket(hdr, buf);
				 packet.scan(Ethernet.ID);				 
				 
				 if(this.readIP4){					 
					 packetInfo = getIpv4Info(packet);
					 if (packetInfo == null && this.readIP6){
					 	packetInfo = getIpv6Info(packet);				 	
					 }					 
				 }else if(this.readIP6){
					 packetInfo = getIpv6Info(packet);
					 if (packetInfo == null && this.readIP4){
					 	packetInfo = getIpv4Info(packet);
					 }
				 }
				 
				 if (packetInfo == null){
					 packetInfo = getVPNInfo(packet);
				 }					 

			 }else{
				 throw new PcapClosedException();
			 }
		 }catch(PcapClosedException e){
			 logger.info("We have read All packets!");
			 throw e;
		 }catch(Exception ex){
			 ex.printStackTrace();
		 }
		 return packetInfo;
	}
	
	private BasicPacketInfo getIpv4Info(PcapPacket packet){
		BasicPacketInfo packetInfo = null;		
		try {
						
			if (packet.hasHeader(ipv4)){
				packetInfo = new BasicPacketInfo(this.generator);
				packetInfo.setSrc(this.ipv4.source());
				packetInfo.setDst(this.ipv4.destination());
				//packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());
				
				if(this.firstPacket == 0L)
					this.firstPacket = packet.getCaptureHeader().timestampInMillis();
				this.lastPacket = packet.getCaptureHeader().timestampInMillis();
					
				
				if(packet.hasHeader(this.tcp)){				
					packetInfo.setSrcPort(tcp.source());
					packetInfo.setDstPort(tcp.destination());
					packetInfo.setProtocol(6);
					packetInfo.setFlagFIN(tcp.flags_FIN());
					packetInfo.setPayloadBytes(tcp.getPayloadLength());
				}else if(packet.hasHeader(this.udp)){
					packetInfo.setSrcPort(udp.source());
					packetInfo.setDstPort(udp.destination());
					packetInfo.setPayloadBytes(udp.getPayloadLength());
					packetInfo.setProtocol(17);			
				}	
			}
		} catch (Exception e) {
			//e.printStackTrace();
			packet.scan(ipv4.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip4())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
			//System.out.println(errormsg);
			logger.error(errormsg);
			//System.exit(-1);
			return null;
		}
		
		return packetInfo;
	}
	
	private BasicPacketInfo getIpv6Info(PcapPacket packet){
		BasicPacketInfo packetInfo = null;
		try{
			if(packet.hasHeader(ipv6)){
				packetInfo = new BasicPacketInfo(this.generator);
				packetInfo.setSrc(this.ipv6.source());
				packetInfo.setDst(this.ipv6.destination());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());			
				
				if(packet.hasHeader(this.tcp)){						
					packetInfo.setSrcPort(tcp.source());
					packetInfo.setDstPort(tcp.destination());
					packetInfo.setPayloadBytes(tcp.getPayloadLength());
					packetInfo.setProtocol(6);
				}else if(packet.hasHeader(this.udp)){
					packetInfo.setSrcPort(udp.source());
					packetInfo.setDstPort(udp.destination());
					packetInfo.setPayloadBytes(udp.getPayloadLength());
					packetInfo.setProtocol(17);								
				}		
			}
		}catch(Exception e){
			e.printStackTrace();
			packet.scan(ipv6.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip6())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
		//	System.out.println(errormsg);
			logger.error(errormsg);
			//System.exit(-1);
			return null;			
		}
				
		return packetInfo;
	}
	
	private BasicPacketInfo getVPNInfo(PcapPacket packet){		
		BasicPacketInfo packetInfo = null;		
		try {
			packet.scan(L2TP.ID);
			
			if (packet.hasHeader(l2tp)){				
		    	if(this.readIP4){		
		    		packet.scan(ipv4.getId());
		    		packetInfo = getIpv4Info(packet);
		    		if (packetInfo == null && this.readIP6){
		    			packet.scan(ipv6.getId());
		    			packetInfo = getIpv6Info(packet);				 	
		    		}					 
		    	}else if(this.readIP6){
		    		packet.scan(ipv6.getId());
		    		packetInfo = getIpv6Info(packet);
		    		if (packetInfo == null && this.readIP4){
		    			packet.scan(ipv4.getId());
		    			packetInfo = getIpv4Info(packet);
		    		}
		    	}				

			}
		} catch (Exception e) {
			e.printStackTrace();
			packet.scan(l2tp.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new L2TP())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
			//System.out.println(errormsg);
			logger.error(errormsg);
			//System.exit(-1);
			return null;
		}
		
		return packetInfo;
	}	

	public long getFirstPacket() {
		return firstPacket;
	}

	public void setFirstPacket(long firstPacket) {
		this.firstPacket = firstPacket;
	}

	public long getLastPacket() {
		return lastPacket;
	}

	public void setLastPacket(long lastPacket) {
		this.lastPacket = lastPacket;
	}	

	
}
