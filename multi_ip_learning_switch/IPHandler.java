package net.floodlightcontroller.iphandler;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
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
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

public class IPHandler implements IFloodlightModule, IOFMessageListener {

	protected static Logger log = LoggerFactory.getLogger(IPHandler.class);
	protected IFloodlightProviderService floodlightProviderService;
	private ConcurrentHashMap<IOFSwitch, HashMap<IPv4Address,ArrayList<NumMacPair>>> controllerDeviceTable;
	private ConcurrentHashMap<IOFSwitch, HashMap<IPv4Address,HashMap<MacAddress,MacAddress>>> controllerMacTable;
	private <T> T search(Iterator<T> itr,T obj) {
		T tmp;
		while(itr.hasNext()) {
			tmp = itr.next();
			if(obj.equals(tmp)) {
				return obj;
			}
		}
		return null;
	}
	private <T extends Comparable<T>> T min(Iterator<T> itr) {
		T tmp = null;
		if(itr.hasNext()) tmp = itr.next();
		else return null;
		T min = tmp;
		while(itr.hasNext()) {
			tmp = itr.next();
			if(tmp.compareTo(min)<0) {
				min = tmp;
			}
		}
		return min;
	}
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "IP Handler";
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

	private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved msg) {
		
		return Command.CONTINUE;
	}

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		HashMap<IPv4Address,ArrayList<NumMacPair>> deviceTable = controllerDeviceTable.get(sw);
		if(deviceTable==null) {
			deviceTable = new HashMap<>();
			controllerDeviceTable.put(sw, deviceTable);
		}
		HashMap<IPv4Address,HashMap<MacAddress,MacAddress>> macTable = controllerMacTable.get(sw);
		if(macTable==null) {
			macTable = new HashMap<>();
			controllerMacTable.put(sw, macTable);
		}
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		EthType type = eth.getEtherType();
		if(type.equals(EthType.ARP)) {
			ARP arp = (ARP) eth.getPayload();
			short prtType = arp.getProtocolType();
			/*
			 * If it is not an IPv4 ARP packet then we ignore it.
			 */
			if (prtType != 0x0800) {
				log.info("Not an IPv4 ARP");
				return Command.CONTINUE;
			}
			
			MacAddress srcMac = arp.getSenderHardwareAddress();
			MacAddress destMac = arp.getTargetHardwareAddress();
			IPv4Address srcIP = arp.getSenderProtocolAddress();
			IPv4Address destIP = arp.getTargetProtocolAddress();
			
			if(arp.getOpCode().equals(ArpOpcode.REQUEST)) {
				ArrayList<NumMacPair> nummac = deviceTable.get(srcIP);
				if(nummac==null) {
					nummac = new ArrayList<>();
					nummac.add(new NumMacPair(srcMac,0));
					deviceTable.put(srcIP, nummac);
				}else {
					if(search(nummac.iterator(),new NumMacPair(srcMac,0))==null) {
						nummac.add(new NumMacPair(srcMac,0));
					}
				}
				HashMap<MacAddress,MacAddress> macPair = macTable.get(destIP);
				if(macPair==null||(!macPair.containsKey(srcMac))) {
					nummac = deviceTable.get(destIP);
					if(nummac!=null&&nummac.size()!=0) {
						NumMacPair pair  = min(nummac.iterator());
						pair.increment();
						nummac.remove(pair);
						nummac.add(pair);
						MacAddress arpMac = pair.getMac();
						Ethernet repEth = new Ethernet();
						repEth.setDestinationMACAddress(srcMac);
						repEth.setEtherType(EthType.ARP);
						repEth.setSourceMACAddress(arpMac);
						repEth.setVlanID(eth.getVlanID());
						ARP repArp = new ARP();
						repArp.setHardwareType(arp.getHardwareType());
						repArp.setProtocolType(arp.getProtocolType());
						repArp.setHardwareAddressLength(arp.getHardwareAddressLength());
						repArp.setProtocolAddressLength(arp.getProtocolAddressLength());
						repArp.setOpCode(ArpOpcode.REPLY);
						repArp.setSenderHardwareAddress(arpMac);
						repArp.setSenderProtocolAddress(destIP);
						repArp.setTargetHardwareAddress(srcMac);
						repArp.setTargetProtocolAddress(srcIP);
						repEth.setPayload(repArp);
						byte[] data = repEth.serialize();
						OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(data)
								.setActions(Collections
										.singletonList((OFAction) sw.getOFFactory().actions().output(inPort, 0xffFFffFF)))
								.setInPort(OFPort.CONTROLLER).build();
						
						sw.write(po);
						boolean nullBool = false;
						if(macPair==null) {
							macPair = new HashMap<>();
							nullBool = true;
						}
						macPair.put(srcMac, arpMac);
						if(nullBool)
						macTable.put(destIP, macPair);
						return Command.STOP;
					}
				}else {
					MacAddress arpMac = macPair.get(srcMac);
					Ethernet repEth = new Ethernet();
					repEth.setDestinationMACAddress(srcMac);
					repEth.setEtherType(EthType.ARP);
					repEth.setSourceMACAddress(arpMac);
					repEth.setVlanID(eth.getVlanID());
					ARP repArp = new ARP();
					repArp.setHardwareType(arp.getHardwareType());
					repArp.setProtocolType(arp.getProtocolType());
					repArp.setHardwareAddressLength(arp.getHardwareAddressLength());
					repArp.setProtocolAddressLength(arp.getProtocolAddressLength());
					repArp.setOpCode(ArpOpcode.REPLY);
					repArp.setSenderHardwareAddress(arpMac);
					repArp.setSenderProtocolAddress(destIP);
					repArp.setTargetHardwareAddress(srcMac);
					repArp.setTargetProtocolAddress(srcIP);
					repEth.setPayload(repArp);
					byte[] data = repEth.serialize();
					OFPacketOut po = sw.getOFFactory().buildPacketOut().setData(data)
							.setActions(Collections
									.singletonList((OFAction) sw.getOFFactory().actions().output(inPort, 0xffFFffFF)))
							.setInPort(OFPort.CONTROLLER).build();
					
					sw.write(po);
					return Command.STOP;
				}
			}
			else if(arp.getOpCode().equals(ArpOpcode.REPLY)) {
				ArrayList<NumMacPair> macPair = deviceTable.get(srcIP);
				if(macPair==null||(search(macPair.iterator(),new NumMacPair(srcMac,0))==null)) {
					boolean b = false;
					if(macPair == null) {
						macPair = new ArrayList<>();
						b = true;
					}
					macPair.add(new NumMacPair(srcMac,0));
					if(b) {
						deviceTable.put(srcIP,macPair);
					}
				}
				macPair = deviceTable.get(destIP);
				if(macPair==null||search(macPair.iterator(),new NumMacPair(srcMac,0))==null) {
					boolean b = false;
					if(macPair==null) {
						macPair = new ArrayList<>();
						b = true;
					}
					macPair.add(new NumMacPair(destMac,1));
					if(b) deviceTable.put(destIP,macPair);
				}else {
					Iterator<NumMacPair> itr = macPair.iterator();
					NumMacPair pair = search(itr,new NumMacPair(destMac,0));
					macPair.remove(pair);
					pair.increment();
					macPair.add(pair);
				}
				HashMap<MacAddress,MacAddress> entryTable = macTable.get(destIP);
				if(entryTable==null||!entryTable.containsKey(srcMac)) {
					boolean b = false;
					if(entryTable==null) {
						entryTable = new HashMap<>();
						b = true;
					}
					entryTable.put(srcMac, destMac);
					if(b) {
						macTable.put(destIP,entryTable);
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
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		log.info("IPHandler Learning switch Starting....");
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		controllerDeviceTable = new ConcurrentHashMap<>();
		controllerMacTable = new ConcurrentHashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);
		floodlightProviderService.addOFMessageListener(OFType.ERROR, this);
		ArrayList<NumMacPair> set = new ArrayList<>();
		MacAddress mac1 = MacAddress.of("00:00:00:00:00:01");
		set.add(new NumMacPair(mac1,1));
		if(search(set.iterator(),new NumMacPair(mac1,0))!=null)
		log.info("Yes, I am doing right");
		else log.info("No, I am doing wrong");
	}

}
