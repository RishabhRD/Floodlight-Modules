package net.floodlightcontroller.multi_ip_learning_switch;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
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
	private ConcurrentHashMap<IOFSwitch, ConcurrentHashMap<IPv4Address, MacAddress>> controllerTable; // Unified ARP
																										// table for
																										// controller

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
		/**
		 * Creating new instance of ARP table for a switch if it is not registered yet
		 */
		ConcurrentHashMap<IPv4Address, MacAddress> switchTable = controllerTable.get(sw);
		if (switchTable == null) {
			log.info("Switch {} is not registered. Registering....", sw);
			switchTable = new ConcurrentHashMap<>();
			controllerTable.put(sw, switchTable);
		}

		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT)); // Input Port for Incoming Packet

		// Extracting Ethernet packet for maintaining ARP table.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		EthType type = eth.getEtherType();

		/**
		 * If Ethernet payload is an IPv4 header then we just note entry in ARP table of
		 * corresponding switch.// Extracting
																													// ethernet
																													// packet
																													// for
																													// maintaining
																													// arp
																													// table.
		 */
		if (type.equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcAddress = ip.getSourceAddress();
			MacAddress srcMac = switchTable.get(srcAddress);
			MacAddress srcPacketMac = eth.getSourceMACAddress();
			if (srcMac == null) {
				switchTable.put(srcAddress, srcPacketMac);
			} else if (!srcMac.equals(srcPacketMac)) {
				switchTable.remove(srcAddress);
				switchTable.put(srcAddress, srcPacketMac);
			}
			return Command.CONTINUE;
		}
		/**
		 * If it is an ARP packet then we do following operations:
		 */
		else if (type.equals(EthType.ARP)) {
			ARP arp = (ARP) eth.getPayload();
			short prtType = arp.getProtocolType();

			/*
			 * If it is not an IPv4 ARP packet then we ignore it.
			 */
			if (prtType != 0x0800) {
				log.info("Not an IPv4 ARP");
				return Command.CONTINUE;
			}

			/**
			 * If it is an ARP reply then we use it for maintaining our ARP table and
			 * updating it if it is outdated.
			 */
			if (arp.getOpCode().equals(ArpOpcode.REPLY)) {
				IPv4Address srcIPAddress = arp.getSenderProtocolAddress();
				MacAddress srcMacAddress = arp.getSenderHardwareAddress();
				IPv4Address targetIPAddress = arp.getTargetProtocolAddress();
				MacAddress targetMacAddress = arp.getSenderHardwareAddress();
				MacAddress tmpMac = switchTable.get(srcIPAddress);
				if (tmpMac == null) {
					switchTable.put(srcIPAddress, srcMacAddress);
				} else if (!tmpMac.equals(srcMacAddress)) {
					switchTable.remove(srcIPAddress);
					switchTable.put(srcIPAddress, srcMacAddress);
				}
				tmpMac = switchTable.get(targetIPAddress);
				if (tmpMac == null) {
					switchTable.put(targetIPAddress, targetMacAddress);
				} else if (!tmpMac.equals(targetMacAddress)) {
					switchTable.remove(targetIPAddress);
					switchTable.put(targetIPAddress, targetMacAddress);
				}
				return Command.CONTINUE;
			}

			/**
			 * If it is an ARP request then its source MAC and source IP part would help us
			 * to maintain our ARP table. For target IP address we check if its entry is
			 * there in ARP table. If entry is there then we send an ARP reply from
			 * controller itself and stop the processing of the packet here only(as no one
			 * should get duplicate ARP reply) Otherwise we do not disturb the packet and
			 * continue its processing.
			 */
			else if (arp.getOpCode().equals(ArpOpcode.REQUEST)) {
				// Maintaining ARP table
				IPv4Address srcIPAddress = arp.getSenderProtocolAddress();
				MacAddress srcMacAddress = arp.getSenderHardwareAddress();
				IPv4Address targetIPAddress = arp.getTargetProtocolAddress();
				MacAddress tmpMac = switchTable.get(srcIPAddress);
				if (tmpMac == null) {
					switchTable.put(srcIPAddress, srcMacAddress);
				} else if (!srcMacAddress.equals(tmpMac)) {
					switchTable.remove(srcIPAddress);
					switchTable.put(srcIPAddress, srcMacAddress);
				}

				// If entry not found continue (our learning switch will broadcast it)
				MacAddress replyMac = switchTable.get(targetIPAddress);
				if (replyMac == null) {
					return Command.CONTINUE;
				}

				// Create an ARP reply and send to required host
				else {
					log.info("Creating pseudo-ARP reply");
					Ethernet repEth = new Ethernet();
					repEth.setDestinationMACAddress(srcMacAddress);
					repEth.setEtherType(EthType.ARP);
					repEth.setSourceMACAddress(replyMac);
					repEth.setVlanID(eth.getVlanID());
					ARP repArp = new ARP();
					repArp.setHardwareType(arp.getHardwareType());
					repArp.setProtocolType(arp.getProtocolType());
					repArp.setHardwareAddressLength(arp.getHardwareAddressLength());
					repArp.setProtocolAddressLength(arp.getProtocolAddressLength());
					repArp.setOpCode(ArpOpcode.REPLY);
					repArp.setSenderHardwareAddress(replyMac);
					repArp.setSenderProtocolAddress(targetIPAddress);
					repArp.setTargetHardwareAddress(srcMacAddress);
					repArp.setTargetProtocolAddress(srcIPAddress);
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
		controllerTable = new ConcurrentHashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);
		floodlightProviderService.addOFMessageListener(OFType.ERROR, this);
	}

}
