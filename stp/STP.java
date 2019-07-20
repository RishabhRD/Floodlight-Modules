package net.floodlightcontroller.stp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortConfig;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFPortMod;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;

public class STP implements IFloodlightModule, IOFSwitchListener, IOFMessageListener {
	protected static Logger log;
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private volatile int numpos = 0;
	private IOFSwitch root = null;
	private ConcurrentHashMap<IOFSwitch, PortCost> map;
	private ConcurrentHashMap<IOFSwitch, HashSet<OFPort>> disabledPorts;
	private MacAddress ctrlMac = MacAddress.of("aa:a1:aa:a1:aa:a1");
	private IPv4Address ctrlIP = IPv4Address.of("12.0.0.1");
	private TransportPort ctrlPort = TransportPort.of(12345);

	@Override
	public String getName() {
		return "STP";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {

		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return type.equals(OFType.PACKET_IN) && name.equals("linkdiscovery");
	}

	private void sendPortMod(IOFSwitch sw, OFPort port, boolean enabled) {
		log.info("CHANGING SWITCH CONF");
		OFPortMod.Builder builder = sw.getOFFactory().buildPortMod();
		HashSet<OFPortConfig> set = new HashSet<>();
		if (!enabled) {
			set.add(OFPortConfig.PORT_DOWN);
		}
		HashSet<OFPortConfig> mask = new HashSet<>();
		mask.add(OFPortConfig.PORT_DOWN);
		OFPortMod mod = builder.setPortNo(port).setConfig(set).setMask(mask).setAdvertise(0x0)
				.setHwAddr(sw.getPort(port).getHwAddr()).build();
		sw.write(mod);
	}

	private void setPort(IOFSwitch sw, OFPort port, boolean enabled) {
		if (enabled) {
			if (disabledPorts.get(sw) == null) {
				sendPortMod(sw, port, true);
			} else {
				disabledPorts.get(sw).remove(port);
				sendPortMod(sw, port, true);
				if (disabledPorts.get(sw).isEmpty())
					disabledPorts.remove(sw);
			}
		} else {
			if (disabledPorts.get(sw) == null) {
				disabledPorts.put(sw, new HashSet<OFPort>());
			}
			disabledPorts.get(sw).add(port);
			sendPortMod(sw, port, false);
		}
	}

	private void enableAllPorts(IOFSwitch sw) {
		if (sw == null)
			return;
		HashSet<OFPort> set = disabledPorts.get(sw);
		if (set == null)
			return;
		Iterator<OFPort> itr = set.iterator();
		while (itr.hasNext()) {
			setPort(sw, itr.next(), true);
		}
	}

	private void enableAllSwitches() {
		Iterator<IOFSwitch> ports = disabledPorts.keySet().iterator();
		if (ports == null)
			return;
		while (ports.hasNext()) {
			IOFSwitch tmp = ports.next();
			enableAllPorts(tmp);
			disabledPorts.remove(tmp);
		}
	}

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		if (!map.containsKey(sw)) {
			if (map.isEmpty()) {
				map.put(sw, new PortCost(null, 0));
				root = sw;
				numpos = 1;
			} else {
				map.put(sw, new PortCost(null, -1));
			}
		}
		if (sw.equals(root)) {
			if (numpos == map.size()) {
				return Command.CONTINUE;
			}
			return Command.STOP;
		}
		OFPort inPort = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort()
				: msg.getMatch().get(MatchField.IN_PORT));
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (eth.getSourceMACAddress().equals(ctrlMac)) {
			log.info("{} GOT THE PACKET", sw);
			IPv4 ip = (IPv4) eth.getPayload();
			UDP udp = (UDP) ip.getPayload();
			String str = new String(udp.getPayload().serialize());
			int suggestedCost = 0;
			try {
				suggestedCost = Integer.parseInt(str)+1;
				log.info("Suggested Cost: {}", suggestedCost);
			} catch (Exception e) {
				return Command.STOP;
			}
			if (map.get(sw).cost < 0) {
				map.get(sw).cost = suggestedCost;
				map.get(sw).port = inPort;
				numpos++;
				floodPacket(sw, new Data(Integer.toString(suggestedCost).getBytes()), inPort);
				log.info("GOT TO CHANGE FROM INFINITY");
			} else if (suggestedCost < map.get(sw).cost) {
				setPort(sw, map.get(sw).port, false);
				map.get(sw).port = inPort;
				map.get(sw).cost = suggestedCost;
				floodPacket(sw, new Data(Integer.toString(suggestedCost).getBytes()), inPort);
				log.info("GOT TO CHANGE TO LOW");
			} else if (suggestedCost >= map.get(sw).cost) {
				setPort(sw, inPort, false);
				log.info("IGNORING HIGH SUGGESTION");
			}
			log.info("POSITIVE NUMBERS: {}", numpos);
			log.info("MAP SIZE: {}", map.size());
			return Command.STOP;
		} else if (numpos != map.size())
			return Command.STOP;
		//log.info("Packet sent out");
		return Command.CONTINUE;
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		return processPacketInMessage(sw, (OFPacketIn) msg, cntx);
	}

	private void floodPacket(IOFSwitch sw, Data data, OFPort inPort) {
		if (inPort == null) {
			writePacketOut(sw, data, OFPort.FLOOD);
		}
		Iterator<OFPort> itr = sw.getEnabledPortNumbers().iterator();
		while (itr.hasNext()) {
			OFPort next = itr.next();

			if (!next.equals(inPort)) {
				continue;
			}

			writePacketOut(sw, data, next);

		}
	}

	private void writePacketOut(IOFSwitch sw, Data data, OFPort outPort) {
		log.info("Writing Packet OUT");
		Ethernet eth = new Ethernet();
		eth.setSourceMACAddress(ctrlMac);
		eth.setDestinationMACAddress(MacAddress.BROADCAST);
		eth.setEtherType(EthType.IPv4);
		IPv4 repIP = new IPv4();
		repIP.setDestinationAddress(IPv4Address.of("255.255.255.255"));
		repIP.setSourceAddress(ctrlIP);
		repIP.setTtl((byte) 32);
		repIP.setProtocol(IpProtocol.UDP);
		repIP.setChecksum((short) 0);
		repIP.setIdentification((short) 0);
		repIP.setFlags((byte) 0);
		repIP.setFragmentOffset((short) 0);
		repIP.setVersion((byte) 4);
		UDP udp = new UDP();
		udp.setDestinationPort(ctrlPort);
		udp.setSourcePort(ctrlPort);
		udp.setChecksum((short) 0);
		eth.setPayload(repIP);
		repIP.setPayload(udp);
		udp.setPayload(data);
		byte[] bytes = eth.serialize();
		OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
				.setData(bytes)
				.setActions(
						Collections.singletonList((OFAction) sw.getOFFactory().actions().output(outPort, 0xffFFffFF)))
				.setInPort(OFPort.CONTROLLER).build();

		sw.write(po);
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		enableAllSwitches();
		IOFSwitch sw = switchService.getActiveSwitch(switchId);
		log.info("SWITCH ADDED: {}",sw);
		numpos = 1;
		if (map.size() == 0) {
			log.info("ELECTING ROOT: {}",sw);
			map.put(sw, new PortCost(null, 0));
			root = sw;
			return;
		} else {
			map.put(sw, new PortCost(null, -1));
			floodPacket(root, new Data(new String("0").getBytes()), null);
			Iterator<IOFSwitch> itr = map.keySet().iterator();
			while (itr.hasNext()) {
				IOFSwitch next = itr.next();
				if (next.equals(root))
					continue;
				map.get(next).cost = -1;
				map.get(next).port = null;
			}
		}
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		log.info("SWITCH REMOVED");
		IOFSwitch sw = switchService.getActiveSwitch(switchId);
		map.remove(sw);
		disabledPorts.remove(sw);
		enableAllSwitches();
		if (map.isEmpty()) {
			root = null;
			numpos = 0;
		} else {
			numpos=1;
			Iterator<IOFSwitch> itr = map.keySet().iterator();
			if(sw.equals(root)) {
				IOFSwitch tmp = itr.next();
				map.get(tmp).cost = 0;
				map.get(tmp).port = null;
				root = tmp;
			}
			if (map.size() == 1) return;
			while (itr.hasNext()) {
				IOFSwitch next = itr.next();
				map.get(next).cost = -1;
				map.get(next).port = null;
			}
			floodPacket(root, new Data(new String("0").getBytes()), null);
		}
	}

	@Override
	public void switchActivated(DatapathId switchId) {
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		/*
		numpos = 1;
		log.info("SWITCH PORT CHANGED");
		enableAllSwitches();
		Iterator<IOFSwitch> itr = map.keySet().iterator();
		while (itr.hasNext()) {
			IOFSwitch next = itr.next();
			map.get(next).cost = -1;
			map.get(next).port = null;
		}
		map.get(root).cost = 0;
		floodPacket(root, new Data(new String("0").getBytes()), null);
		*/
	}

	@Override
	public void switchChanged(DatapathId switchId) {
	}

	@Override
	public void switchDeactivated(DatapathId switchId) {
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> i = new ArrayList<>();
		i.add(IFloodlightProviderService.class);
		i.add(IOFSwitchService.class);
		return i;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		log = LoggerFactory.getLogger(STP.class);
		map = new ConcurrentHashMap<>();
		disabledPorts = new ConcurrentHashMap<>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);
	}

}
