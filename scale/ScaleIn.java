package net.floodlightcontroller.scale;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFFlowRemovedReason;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.ArpOpcode;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import java.util.ArrayList;

import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.projectfloodlight.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScaleIn implements IFloodlightModule, IOFMessageListener {
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger log;
	private HashMap<MacAddress, String> vethTable;
	private HashMap<MacAddress, Integer> serverTable;
	private HashMap<MacAddress, MacBool> clientTable;
	private final long defaultIdleTimeOut = 1; // in seconds
	private final long defaultHardTimeout = 0; // in seconds
	private final IPv4Address ctrlIP = IPv4Address.of("12.255.255.253");
	private final TransportPort ctrlPort = TransportPort.of(10101);
	private final MacAddress ctrlMacAddress = MacAddress.of("ff:ff:ff:ff:ff:1f");
	private final IPv4Address serverIP = IPv4Address.of("12.0.0.2");
	private final TransportPort serverPort = TransportPort.of(11111);
	private final IPv4Address hostIP = IPv4Address.of("12.255.255.254");
	private final TransportPort hostPort = TransportPort.of(10101);
	private final MacAddress hostMac = MacAddress.of("");
	public static final int SCALE_APP_ID = 13;
	public static final int APP_ID_BITS = 12;
	public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
	public static final long SCALE_COOKIE = (long) (SCALE_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "Scale";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> i = new ArrayList<>();
		i.add(IFloodlightProviderService.class);
		return i;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		log = LoggerFactory.getLogger(ScaleIn.class);
		vethTable = new HashMap<>();
		serverTable = new HashMap<>();
		clientTable = new HashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
	}
	
	private void sendScaleMessage(IOFSwitch sw,OFPort in,byte[] data) {
		Ethernet replyEther = new Ethernet();
		replyEther.setDestinationMACAddress(hostMac);
		replyEther.setEtherType(EthType.IPv4);
		replyEther.setSourceMACAddress(ctrlMacAddress);
		replyEther.setVlanID((short) 0);
		IPv4 repIP = new IPv4();
		repIP.setDestinationAddress(hostIP);
		repIP.setSourceAddress(ctrlIP);
		repIP.setTtl((byte) 32);
		repIP.setProtocol(IpProtocol.UDP);
		repIP.setChecksum((short) 0);
		repIP.setIdentification((short) 0);
		repIP.setFlags((byte) 0);
		repIP.setFragmentOffset((short) 0);
		repIP.setVersion((byte) 4);
		UDP udp = new UDP();
		udp.setDestinationPort(hostPort);
		udp.setSourcePort(ctrlPort);
		udp.setChecksum((short) 0);
		Data dt = new Data();
		dt.setData(data);
		replyEther.setPayload(repIP);
		repIP.setPayload(udp);
		udp.setPayload(dt);
		OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(replyEther.serialize())
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions()
						.output(in, 0xffFFffFF)))
				.setInPort(OFPort.CONTROLLER).build();

		sw.write(po);
	}

	private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved msg) {

		if (msg.getReason().equals(OFFlowRemovedReason.IDLE_TIMEOUT)) {
			Match match = msg.getMatch();
			IPv4Address src = match.get(MatchField.IPV4_SRC);
			IPv4Address dest = match.get(MatchField.IPV4_DST);
			if (src.equals(serverIP)) {
				if (match.get(MatchField.IP_PROTO).equals(IpProtocol.TCP)
						&& match.get(MatchField.TCP_SRC).equals(serverPort)) {
					MacAddress destMac = match.get(MatchField.ETH_DST);
					MacAddress srcMac = match.get(MatchField.ETH_SRC);
					MacBool tmpBool = clientTable.get(destMac);
					if (tmpBool == null)
						return Command.CONTINUE;
					clientTable.replace(destMac, new MacBool(tmpBool.getMac(), true, tmpBool.clietDeletedTag()));
					tmpBool = clientTable.get(destMac);
					if (tmpBool.serverDeletedTag() && tmpBool.clietDeletedTag()) {
						clientTable.remove(destMac);
						int val = serverTable.get(srcMac);
						serverTable.replace(srcMac, val - 1);
						if (val - 1 == 0 && serverTable.size() > 1) {
							serverTable.remove(srcMac);
							sendScaleMessage(sw, match.get(MatchField.IN_PORT), ("STOP " + vethTable.get(srcMac)).getBytes());
							vethTable.remove(srcMac);
						}
					}
				}

			} else if (dest.equals(serverIP)) {
				if (match.get(MatchField.IP_PROTO).equals(IpProtocol.TCP)
						&& match.get(MatchField.TCP_DST).equals(serverPort)) {
					MacAddress destMac = match.get(MatchField.ETH_DST);
					MacAddress srcMac = match.get(MatchField.ETH_SRC);
					MacBool tmpBool = clientTable.get(srcMac);
					if (tmpBool == null)
						return Command.CONTINUE;
					clientTable.replace(srcMac, new MacBool(tmpBool.getMac(), tmpBool.serverDeletedTag(), true));
					tmpBool = clientTable.get(srcMac);
					if (tmpBool.serverDeletedTag() && tmpBool.clietDeletedTag()) {
						clientTable.remove(srcMac);
						int val = serverTable.get(destMac);
						serverTable.replace(destMac, val - 1);
						if (val - 1 == 0 && serverTable.size() > 1) {
							serverTable.remove(destMac);
							Ethernet replyEther = new Ethernet();
							replyEther.setDestinationMACAddress(hostMac);
							replyEther.setEtherType(EthType.IPv4);
							replyEther.setSourceMACAddress(ctrlMacAddress);
							replyEther.setVlanID((short) 0);
							IPv4 repIP = new IPv4();
							repIP.setDestinationAddress(hostIP);
							repIP.setSourceAddress(ctrlIP);
							repIP.setTtl((byte) 32);
							repIP.setProtocol(IpProtocol.UDP);
							repIP.setChecksum((short) 0);
							repIP.setIdentification((short) 0);
							repIP.setFlags((byte) 0);
							repIP.setFragmentOffset((short) 0);
							repIP.setVersion((byte) 4);
							UDP udp = new UDP();
							udp.setDestinationPort(serverPort);
							udp.setSourcePort(ctrlPort);
							udp.setChecksum((short) 0);
							byte[] data = ("STOP " + vethTable.get(destMac)).getBytes();
							Data dt = new Data();
							dt.setData(data);
							replyEther.setPayload(repIP);
							repIP.setPayload(udp);
							udp.setPayload(dt);
							OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(replyEther.serialize())
									.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions()
											.output(match.get(MatchField.IN_PORT), 0xffFFffFF)))
									.setInPort(OFPort.CONTROLLER).build();

							sw.write(po);
							vethTable.remove(destMac);
						}
					}
				}
			}
		}
		return Command.CONTINUE;
	}

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn msg,FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress destMac = eth.getDestinationMACAddress();
		OFPort inPort = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort()
				: msg.getMatch().get(MatchField.IN_PORT));
		if(eth.getEtherType().equals(EthType.ARP)){
			ARP arp = (ARP)eth.getPayload();
			
			if(arp.getOpCode().equals(ArpOpcode.REQUEST)&&arp.getTargetProtocolAddress().equals(ctrlIP)) {
				ARP reply = new ARP();
				reply.setHardwareType(arp.getHardwareType());
				reply.setHardwareAddressLength(arp.getHardwareAddressLength());
				reply.setProtocolType(arp.getProtocolType());
				reply.setProtocolAddressLength(arp.getProtocolAddressLength());
				reply.setOpCode(ArpOpcode.REPLY);
				reply.setSenderProtocolAddress(arp.getTargetProtocolAddress());
				reply.setSenderHardwareAddress(ctrlMacAddress);
				reply.setTargetProtocolAddress(arp.getSenderProtocolAddress());
				reply.setTargetHardwareAddress(arp.getSenderHardwareAddress());
				Ethernet replyEther = new Ethernet();
				replyEther.setDestinationMACAddress(arp.getSenderHardwareAddress());
				replyEther.setEtherType(EthType.ARP);
				replyEther.setSourceMACAddress(ctrlMacAddress);
				replyEther.setVlanID(eth.getVlanID());
				replyEther.setPayload(reply);
				byte[] data = replyEther.serialize();
				OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(data)
						.setActions(Collections
								.singletonList((OFAction) sw.getOFFactory().actions().output(inPort, 0xffFFffFF)))
						.setInPort(OFPort.CONTROLLER).build();
				
				sw.write(po);
				return Command.STOP;
			}else if(arp.getTargetProtocolAddress().equals(serverIP)){
				Iterator<MacAddress> itr = serverTable.keySet().iterator();
				MacAddress min = itr.next();
				int val = serverTable.get(min);
				while(itr.hasNext()) {
					MacAddress tmpMac = itr.next();
					int tmpSize = serverTable.get(tmpMac);
					if(tmpSize<val) {
						min = tmpMac;
					}
				}
				ARP reply = new ARP();
				reply.setHardwareType(arp.getHardwareType());
				reply.setHardwareAddressLength(arp.getHardwareAddressLength());
				reply.setProtocolType(arp.getProtocolType());
				reply.setProtocolAddressLength(arp.getProtocolAddressLength());
				reply.setOpCode(ArpOpcode.REPLY);
				reply.setSenderProtocolAddress(arp.getTargetProtocolAddress());
				reply.setSenderHardwareAddress(min);
				reply.setTargetProtocolAddress(arp.getSenderProtocolAddress());
				reply.setTargetHardwareAddress(arp.getSenderHardwareAddress());
				Ethernet replyEther = new Ethernet();
				replyEther.setDestinationMACAddress(arp.getSenderHardwareAddress());
				replyEther.setEtherType(EthType.ARP);
				replyEther.setSourceMACAddress(min);
				replyEther.setVlanID(eth.getVlanID());
				replyEther.setPayload(reply);
				byte[] data = replyEther.serialize();
				OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(data)
						.setActions(Collections
								.singletonList((OFAction) sw.getOFFactory().actions().output(inPort, 0xffFFffFF)))
						.setInPort(OFPort.CONTROLLER).build();
				
				sw.write(po);
				return Command.STOP;
			}else {
				return Command.CONTINUE;
			}
		}else if(eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIP = ip.getSourceAddress();
			IPv4Address destIP = ip.getDestinationAddress();
			if(destIP.equals(ctrlIP)) {
				if(ip.getProtocol().equals(IpProtocol.UDP)) {
					UDP udp = (UDP)ip.getPayload();
					if(udp.getDestinationPort().equals(ctrlPort)){
						Data data = (Data)udp.getPayload();
						String str = new String(data.getData());
						String[] split = str.split(" ");
						if(split.length==0) {
							return Command.CONTINUE;
						}else {
							if(split[0].equals("START")&&split.length==3) {
								String name = split[1];
								MacAddress vethName = MacAddress.of(split[2]);
								serverTable.put(vethName, 0);
								vethTable.put(vethName, name);
								return Command.STOP;
							}else {
								return Command.CONTINUE;
							}
						}
					}else {
						return Command.CONTINUE;
					}
				} else if(ip.getProtocol().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP)ip.getPayload();
					if(destIP.equals(serverIP)&&tcp.getDestinationPort().equals(serverPort)){
						if(tcp.getFlags()==2) {
							MacAddress min = destMac;
							serverTable.replace(min,serverTable.get(min)+1);
							clientTable.put(srcMac,new MacBool(min,false,false));
							if(serverTable.get(min)>=2) {
								Random rand = new Random(System.currentTimeMillis());
								byte[] data= new byte[8];
								rand.nextBytes(data);
								data = ("START "+new String(data)).getBytes();
								sendScaleMessage(sw, inPort, data);
							} else {
								MacBool tmpBool = clientTable.get(srcMac);
								if(tmpBool==null) return Command.CONTINUE;
								clientTable.replace(srcMac, new MacBool(tmpBool.getMac(),tmpBool.serverDeletedTag(),true));
							}
							return Command.CONTINUE;
						}
					} 
				}
			}else if(srcIP.equals(serverIP)) {
				 if(ip.getProtocol().equals(IpProtocol.TCP)) {
						TCP tcp = (TCP)ip.getPayload();
						if(tcp.getSourcePort().equals(serverPort)) {
							MacBool tmpBool = clientTable.get(destMac);
							if(tmpBool==null) return Command.CONTINUE;
							clientTable.replace(destMac, new MacBool(tmpBool.getMac(),false,tmpBool.clietDeletedTag()));
						}
				 }
			}
		}
		return Command.CONTINUE;
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub

		switch (msg.getType()) {
		case PACKET_IN:
			return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
		case FLOW_REMOVED:
			return this.processFlowRemovedMessage(sw, (OFFlowRemoved) msg);
		case ERROR:
			log.info("received an error {} from switch {}", msg, sw);
			return Command.CONTINUE;
		default:
			log.error("received an unexpected message {} from switch {}", msg, sw);
			return Command.CONTINUE;
		}

	}

}
